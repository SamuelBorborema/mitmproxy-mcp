import asyncio
import contextlib
import logging
import os
import sys
import json
import time
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl
import re
import re2

import structlog

from mcp.server.mcpserver import MCPServer
from mcp.shared.subscriptions import ResourceUpdated
from mcp.types import ToolAnnotations
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from curl_cffi.requests import AsyncSession
from jsonpath_ng import parse as parse_jsonpath
from bs4 import BeautifulSoup

from ..models import ScopeConfig, InterceptionRule
from .scope import ScopeManager
from .recorder import TrafficRecorder
from .interceptor import TrafficInterceptor
from .generation import normalize_scraper_flows, render_scraper_code

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Configure standard logging to output the JSON string as-is
logging.basicConfig(
    format="%(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)

logger = structlog.get_logger()


class MitmController:
    def __init__(self, dump_file: Optional[str] = None):
        self.master: Optional[DumpMaster] = None
        self.proxy_task: Optional[asyncio.Task] = None
        self.scope_config = ScopeConfig()
        self.scope_manager = ScopeManager(self.scope_config)
        self.recorder = TrafficRecorder(self.scope_manager)
        self.interceptor = TrafficInterceptor()
        self.running = False
        self.port = 8080
        self.host = "127.0.0.1"
        self.session_variables = {}
        self.dump_file = dump_file
        self.cli_upstream_proxy: Optional[str] = None
        self.default_port = 8080
        self.default_host = "127.0.0.1"
        self.auto_start = False
        self.started_at: Optional[float] = None

    def _get_verify_param(self, verify_override: Optional[bool] = None) -> Any:
        if verify_override is not None:
            return verify_override

        cert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
        if os.path.exists(cert_path):
            return cert_path

        return True

    async def start(
        self,
        port: int = 8080,
        host: str = "127.0.0.1",
        dump_file: Optional[str] = None,
        upstream_proxy: Optional[str] = None,
    ):
        if self.running:
            return "MITM is already running."

        self.port = port
        self.host = host
        opts = options.Options(listen_host=host, listen_port=port)

        up_proxy = upstream_proxy or self.cli_upstream_proxy
        if up_proxy:
            opts.update(mode=f"upstream:{up_proxy}")
            logger.info("upstream_proxy_configured", url=up_proxy)

        self.master = DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        self.master.addons.add(self.recorder)
        self.master.addons.add(self.interceptor)

        save_path = dump_file or self.dump_file
        if save_path:
            opts.update(save_stream_file=save_path)
            logger.info("flow_dump_enabled", path=save_path)

        # pre-check: fail fast if the port is taken. mitmproxy's master.run() dies
        # async with SystemExit on bind failure, which would otherwise leave a false
        # "Started" + running=True. A synchronous probe bind is deterministic.
        import socket

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((host, port))
        except OSError as e:
            probe.close()
            self.master = None
            logger.error("proxy_start_failed", host=host, port=port, error=str(e))
            return f"Couldn't start the proxy on {host}:{port}: {e}"
        probe.close()

        self.proxy_task = asyncio.create_task(self.master.run())
        self.running = True
        self.started_at = time.monotonic()
        logger.info("proxy_started", host=host, port=port)
        msg = f"Started proxy on port {port}"
        if save_path:
            msg += f", dumping flows to {save_path}"
        return msg

    async def stop(self):
        if not self.running or not self.master:
            return "The proxy isn't running right now."
        # Explicitly stop all server instances to release the listening port
        # and close all active connections (keepalive connections otherwise persist)
        ps_addon = self.master.addons.get("proxyserver")
        if ps_addon:
            for handler in list(ps_addon.connections.values()):
                try:
                    for transport_io in list(handler.transports.values()):
                        if transport_io.writer and not transport_io.writer.is_closing():
                            transport_io.writer.close()
                except Exception:
                    pass
            for instance in list(ps_addon.servers._instances.values()):
                try:
                    await instance.stop()
                except Exception:
                    pass
            ps_addon.servers._instances.clear()
        self.master.shutdown()
        if self.proxy_task:
            done, _ = await asyncio.wait({self.proxy_task}, timeout=5.0)
            if not done:
                self.proxy_task.cancel()
                try:
                    await self.proxy_task
                except (asyncio.CancelledError, Exception):
                    pass
            self.proxy_task = None
        self.running = False
        self.started_at = None
        logger.info("proxy_stopped")
        return "Stopped the proxy."

    async def replay_request(
        self,
        flow_id: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        timeout: float = 30.0,
    ) -> str:
        """
        Re-executes captured request using curl_cffi
        """
        # Fetch flow details from DB (dict)
        flow_data = self.recorder.get_flow_detail(flow_id)
        if not flow_data:
            return "Couldn't find that flow"

        original_request = flow_data["request"]
        target_url = original_request["url"]
        target_method = method if method else original_request["method"]

        target_headers = dict(original_request["headers"])
        target_headers.pop("Host", None)
        target_headers.pop("Content-Length", None)
        target_headers.pop("Content-Encoding", None)

        if headers:
            target_headers.update(headers)

        target_content = None
        if body is not None:
            target_content = body
        else:
            # Prefer full body from DB; fall back to preview
            flow_obj = self.recorder.db.get_flow_object(flow_id)
            if flow_obj and flow_obj.body is not None:
                target_content = flow_obj.body
            else:
                target_content = original_request.get("body_preview")
            if not target_content:
                target_content = None

        logger.info(
            "replay_request",
            flow_id=flow_id,
            method=target_method,
            url=target_url,
            mode="stealth",
        )

        proxy_url = f"http://127.0.0.1:{self.port}"

        try:
            async with AsyncSession(
                impersonate="chrome120",
                proxies={
                    "http": proxy_url,
                    "https": proxy_url,
                },
                verify=self._get_verify_param(),
                timeout=timeout,
            ) as client:
                request_kwargs = {
                    "method": target_method,
                    "url": target_url,
                    "headers": target_headers,
                }
                if isinstance(target_content, str):
                    request_kwargs["data"] = target_content
                elif isinstance(target_content, bytes):
                    request_kwargs["data"] = target_content

                response = await client.request(**request_kwargs)

            return f"Replayed successfully! (Status: {response.status_code}). Check the traffic summary for the new flow."
        except Exception as e:
            logger.error(f"Replay failed: {e}")
            return f"That didn't work: {str(e)}"


# Global Controller Instance
controller = MitmController()


@contextlib.asynccontextmanager
async def _lifespan(_server):
    if getattr(controller, "auto_start", False) and not controller.running:
        result = await controller.start(port=controller.default_port, host=controller.default_host)
        logger.info("auto_start", result=result)
    try:
        yield
    finally:
        if controller.running:
            await controller.stop()


mcp = MCPServer(name="Mitmproxy Manager", lifespan=_lifespan)

LIVE_FLOWS_URI = "flows://live"


def _notify_live_flow() -> None:
    """Publish ResourceUpdated for flows://live via the server's subscription bus.

    Called from TrafficRecorder hooks (which are synchronous mitmproxy addon
    callbacks). Since those hooks run on the same asyncio loop as the
    DumpMaster task, it is safe to schedule the async publish via
    call_soon_threadsafe / create_task. Do not raise in this path.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    try:
        loop.create_task(mcp._subscriptions.publish(ResourceUpdated(uri=LIVE_FLOWS_URI)))
    except RuntimeError:
        # Fallback if loop is closed or task creation fails
        try:
            asyncio.create_task(mcp._subscriptions.publish(ResourceUpdated(uri=LIVE_FLOWS_URI)))
        except RuntimeError:
            pass
    except Exception as e:  # pragma: no cover - defensive
        print(f"Failed to publish live flow update: {e}", file=sys.stderr)


# Wire live-flow notifications without importing mcp inside recorder.py
controller.recorder.on_flow = _notify_live_flow


@mcp.resource(LIVE_FLOWS_URI, mime_type="application/json", description="Live captured flows (latest 20)")
def live_flows() -> str:
    """Return a snapshot of the latest captured flows as JSON.

    This resource is designed for live subscription: clients can
    `subscriptions/listen` with a filter for this URI and will receive
    `ResourceUpdated` notifications whenever a new flow is saved.
    """
    flows = controller.recorder.get_flow_summary(limit=20)
    return json.dumps(flows, indent=2)


# --- MCP Tools ---


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def start_proxy(
    port: Optional[int] = None,
    dump_file: Optional[str] = None,
    upstream_proxy: Optional[str] = None,
) -> dict[str, Any]:
    """
    Start the mitmproxy instance.
    Args:
        port: Port to listen on. Omit to use the server's configured default
            (--port / MITMPROXY_PORT, else 8080).
        dump_file: Optional file path to save raw mitmproxy .flow data.
            Prefix with + to append to an existing file.
        upstream_proxy: Optional upstream proxy URL (e.g., 'http://user:pass@proxy:port').
    """
    try:
        msg = await controller.start(
            port=port if port is not None else controller.default_port,
            host=controller.default_host,
            dump_file=dump_file,
            upstream_proxy=upstream_proxy,
        )
        if msg.startswith("Couldn't") or "already running" in msg.lower():
            status = "error" if msg.startswith("Couldn't") else "ok"
            return {"status": status, "message": msg}
        port_used = port if port is not None else controller.default_port
        result: dict[str, Any] = {"status": "ok", "message": msg, "port": port_used, "host": controller.default_host}
        if dump_file or controller.dump_file:
            result["dump_file"] = dump_file or controller.dump_file
        if upstream_proxy or controller.cli_upstream_proxy:
            result["upstream_proxy"] = upstream_proxy or controller.cli_upstream_proxy
        return result
    except Exception as e:
        logger.error("proxy_start_failed", error=str(e))
        return {"status": "error", "message": f"Couldn't start the proxy: {str(e)}"}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False))
async def stop_proxy() -> dict[str, Any]:
    msg = await controller.stop()
    status = "ok"
    if "isn't running" in msg.lower():
        status = "ok"
    elif msg.startswith("Couldn't"):
        status = "error"
    return {"status": status, "message": msg}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def set_scope(allowed_domains: List[str]) -> dict[str, Any]:
    controller.scope_manager.update_domains(allowed_domains)
    if allowed_domains:
        domains_str = ", ".join(allowed_domains)
    else:
        domains_str = "everything"
    return {"status": "ok", "message": f"Updated. Now tracking: {domains_str}", "allowed_domains": allowed_domains, "tracking": domains_str}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def set_global_header(key: str, value: str) -> dict[str, Any]:
    rule_id = f"global_{key.lower()}"
    rule = InterceptionRule(
        id=rule_id,
        url_pattern=".*",
        resource_type="request",
        action_type="inject_header",
        key=key,
        value=value,
    )
    controller.interceptor.add_rule(rule)
    return {"status": "ok", "message": f"Set global header: {key} = {value}", "rule_id": rule_id, "key": key, "value": value}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def remove_global_header(key: str) -> dict[str, Any]:
    rule_id = f"global_{key.lower()}"
    controller.interceptor.remove_rule(rule_id)
    return {"status": "ok", "message": f"Removed global header: {key}", "key": key, "rule_id": rule_id}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def get_traffic_summary(limit: int = 20) -> list[dict[str, Any]]:
    flows = controller.recorder.get_flow_summary(limit)
    return flows


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def inspect_flow(flow_id: str, full_body: bool = False) -> dict[str, Any]:
    """
    Get full details of a captured flow.
    Args:
        flow_id: The ID of the captured flow
        full_body: If True, return full request body instead of 2000-char preview
    """
    logger.debug("inspect_flow", flow_id=flow_id)
    data = controller.recorder.get_flow_detail(flow_id)
    if not data:
        return {"error": "Couldn't find that flow.", "flow_id": flow_id}
    if full_body and data.get("request"):
        flow_obj = controller.recorder.db.get_flow_object(flow_id)
        if flow_obj and flow_obj.body is not None:
            data["request"]["body"] = flow_obj.body
            data["request"].pop("body_preview", None)
    return data


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def inspect_flows(
    flow_ids: str,
    fields: str = None,
    full_body: bool = False,
) -> list[dict[str, Any]]:
    """
    Batch inspect multiple flows in one call. Reduces context usage vs
    calling inspect_flow N times.
    Args:
        flow_ids: Comma-separated list of flow IDs to inspect
        fields: Comma-separated list of DB columns to select.
            e.g. "id,url,method,request_headers,request_body" to skip
            response data. Default: all columns.
        full_body: If True, return full request body instead of preview
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    columns = [c.strip() for c in fields.split(",")] if fields else None
    derived_fields = set()
    if columns:
        derived_fields = {c for c in columns if c in {"content_type", "response_content_type"}}
        if derived_fields:
            if "response_headers" not in columns:
                columns.append("response_headers")
            # Remove derived field names before passing to DB query
            columns = [c for c in columns if c not in derived_fields]
    # Always include id in columns
    if columns and "id" not in columns:
        columns.insert(0, "id")

    results = controller.recorder.db.get_by_ids(
        ids, columns=columns, ordered_headers=True
    )

    if derived_fields:
        for entry in results:
            headers = entry.get("response", {}).get("headers") or []
            header_dict = {k.lower(): v for k, v in headers}
            content_type = header_dict.get("content-type", "unknown")
            if "content_type" in derived_fields:
                entry["content_type"] = content_type
            if "response_content_type" in derived_fields:
                entry["response_content_type"] = content_type

    if full_body and not columns:
        # Replace truncated previews with full bodies
        for entry in results:
            req = entry.get("request")
            if req:
                flow_obj = controller.recorder.db.get_flow_object(entry["id"])
                if flow_obj and flow_obj.body is not None:
                    req["body"] = flow_obj.body

    return results


def _json_type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int) and not isinstance(value, bool):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    if value is None:
        return "null"
    return type(value).__name__


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def get_flow_schema(flow_id: str) -> dict[str, str]:
    """Infer a simple schema from a flow's JSON response body."""
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return {"error": "Flow not found."}

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None

    flow_obj = controller.recorder.db.get_flow_object(flow_id)
    response_obj = getattr(flow_obj, "response", None) if flow_obj else None
    full_content = getattr(response_obj, "content", None) if response_obj else None
    if full_content:
        if isinstance(full_content, bytes):
            body_content = full_content.decode("utf-8", errors="replace")
        else:
            body_content = str(full_content)

    if not body_content:
        return {"error": "Flow has no response body."}

    try:
        data = json.loads(body_content)
    except json.JSONDecodeError:
        return {"error": "Response body is not valid JSON."}

    if not isinstance(data, dict):
        return {"error": f"Response is JSON but not an object (it's {type(data).__name__})."}

    schema = {key: _json_type_name(value) for key, value in data.items()}
    return schema


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False))
async def load_traffic_file(
    file_path: str,
    append: bool = False,
    scope: str = None,
) -> dict[str, Any]:
    """
    Import flows from a HAR or mitmproxy flow file into the traffic database.
    After import, all traffic inspection tools work on the imported data.
    No proxy needs to be running.
    Args:
        file_path: Path to .har or .mitm/.flow file
        append: If True, keep existing traffic. If False (default), clear first.
        scope: Comma-separated list of domains to filter by during import.
            Only flows matching these domains are imported.
    """
    scope_list = (
        [d.strip() for d in scope.split(",") if d.strip()] if scope else None
    )

    # Security: Prevent path traversal and restrict to working directory
    try:
        requested_path = Path(file_path).resolve()
        base_dir = Path.cwd().resolve()
        if not str(requested_path).startswith(str(base_dir)):
            return {
                "status": "error",
                "message": f"Security Error: Access denied to {file_path}. Path must be within the project directory."
            }
    except Exception as e:
        return {"status": "error", "message": f"Invalid path: {str(e)}"}

    try:
        stats = await asyncio.to_thread(
            controller.recorder.db.import_from_file,
            str(requested_path), append=append, scope=scope_list
        )
        return {
                "status": "ok",
                "imported": stats["imported"],
                "skipped": stats["skipped"],
                "errors": stats["errors"],
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def extract_from_flow(flow_id: str, json_path: str = None, css_selector: str = None) -> list[Any] | dict[str, Any]:
    """
    Extract specific data from a flow's response body using JSONPath or CSS
    selectors.
    Args:
        flow_id: The ID of the captured flow
        json_path: A JSONPath expression to extract data from a JSON response
        css_selector: A CSS selector to extract data from an HTML/XML response
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return {"error": "No matching flow."}

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None
    if not body_content:
        return {"error": "Flow has no response body."}

    if json_path:
        try:
            # Parse body as JSON
            data = json.loads(body_content)
            # Apply JSONPath
            jsonpath_expr = parse_jsonpath(json_path)
            matches = [match.value for match in jsonpath_expr.find(data)]
            return matches
        except json.JSONDecodeError:
            return {"error": "Response body is not valid JSON."}
        except Exception as e:
            return {"error": f"Error executing JSONPath: {str(e)}"}

    if css_selector:
        try:
            soup = BeautifulSoup(body_content, "html.parser")
            elements = soup.select(css_selector)

            result = []
            for el in elements:
                result.append({"text": el.get_text(strip=True), "html": str(el), "attrs": el.attrs})

            return result
        except Exception as e:
            return {"error": f"Error executing CSS Selector: {str(e)}"}

    return {"error": "You must provide a json_path or a css_selector."}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def search_traffic(
    query: str = None,
    domain: str = None,
    method: str = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Search captured traffic using filters.
    Args:
        query: Keywords to search in URL or body
        domain: Filter by domain name
        method: Filter by HTTP method (GET, POST, etc.)
        limit: Max results to return
    """
    results = controller.recorder.search(query, domain, method, limit)
    return results


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def set_session_variable(name: str, value: str) -> dict[str, Any]:
    """Manually set a session variable to use in replayed flows."""
    controller.session_variables[name] = value
    return {"status": "ok", "message": f"Set session variable ${name} = {value}", "name": name, "value": value}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def extract_session_variable(
    name: str, flow_id: str, regex_pattern: str, group_index: int = 1
) -> dict[str, Any]:
    """
    Extract a value from a flow's response body using a regex and store it as a session variable.
    Args:
        name: Variable name (referenced as $name in replay_flow)
        flow_id: The ID of the flow to extract from
        regex_pattern: The regex pattern with capture groups
        group_index: Which regex capture group to extract (default: 1)
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return {"status": "error", "message": "No matching flow.", "flow_id": flow_id}

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None
    if not body_content:
        return {"status": "error", "message": "Flow has no response body.", "flow_id": flow_id}
    try:
        match = re2.search(regex_pattern, body_content)
        if match:
            value = match.group(group_index)
            controller.session_variables[name] = value
            return {"status": "ok", "message": f"Extracted and set ${name} = {value}", "name": name, "value": value}
        else:
            return {"status": "error", "message": f"Pattern not found in response body.", "name": name}
    except Exception as e:
        return {"status": "error", "message": f"Error applying regex: {str(e)}"}


def _resolve_template(template_str: str, variables: dict) -> str:
    """Resolves $variable placeholders in a string."""
    result = template_str
    for k, v in variables.items():
        result = result.replace(f"${k}", str(v))
    return result


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False))
async def clear_traffic() -> dict[str, Any]:
    """Clear all captured traffic from the database."""
    controller.recorder.clear()
    return {"status": "ok", "message": "Cleared all traffic history."}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True))
async def fuzz_endpoint(
    flow_id: str,
    target_param: str,
    param_type: str,
    payload_category: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    Fuzz an endpoint by substituting a target parameter with a category of
    DAST payloads.
    Args:
        flow_id: The flow to replay as the base request.
        target_param: The name of the parameter to replace.
        param_type: The location of the parameter: 'query' or 'json_body'.
        payload_category: The category of payloads
        ('sqli', 'xss', 'path_traversal').
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return {"status": "error", "message": "No matching flow.", "flow_id": flow_id}

    if payload_category == "sqli":
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' ORDER BY 1--+",
        ]
    elif payload_category == "xss":
        payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ]
    elif payload_category == "path_traversal":
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/windows/win.ini",
        ]
    else:
        return {"status": "error", "message": "Unknown payload category. Use 'sqli', 'xss', or 'path_traversal'.", "payload_category": payload_category}

    original_request = flow_data["request"]
    base_url = original_request["url"]
    method = original_request["method"]

    target_headers = dict(original_request["headers"])
    target_headers.pop("Host", None)
    target_headers.pop("Content-Length", None)
    target_headers.pop("Content-Encoding", None)

    # Get baseline response for anomaly detection
    try:
        baseline_flow = controller.recorder.db.get_flow_object(flow_id)
        if baseline_flow and baseline_flow.response:
            baseline_status = baseline_flow.response.status_code
        else:
            baseline_status = 200

        if baseline_flow and baseline_flow.response and baseline_flow.response.content:
            baseline_len = len(baseline_flow.response.content)
        else:
            baseline_len = 0
    except Exception:
        baseline_status = 200
        baseline_len = 0

    proxy_url = f"http://127.0.0.1:{controller.port}"
    anomalies = []

    async with AsyncSession(
        impersonate="chrome120",
        proxies={"http": proxy_url, "https": proxy_url},
        verify=controller._get_verify_param(),
        timeout=timeout,
    ) as client:
        tasks = []
        for payload in payloads:
            req_url = base_url
            req_body = None

            if param_type == "query":
                parsed_url = urlparse(base_url)
                qs = parse_qsl(parsed_url.query)
                new_qs = [(k, payload if k == target_param else v) for k, v in qs]
                # If param didn't exist, add it
                if target_param not in [k for k, v in qs]:
                    new_qs.append((target_param, payload))

                req_url = parsed_url._replace(query=urlencode(new_qs)).geturl()

                if original_request.get("body_preview"):
                    flow_obj = controller.recorder.db.get_flow_object(flow_id)
                    req_body = flow_obj.body
                    if not req_body:
                        req_body = original_request.get("body_preview")

            elif param_type == "json_body":
                flow_obj = controller.recorder.db.get_flow_object(flow_id)
                body_content = flow_obj.body
                if not body_content:
                    body_content = original_request.get("body_preview", "")

                try:
                    if isinstance(body_content, bytes):
                        body_content = body_content.decode("utf-8")
                    body_data = json.loads(body_content)
                    if target_param in body_data:
                        body_data[target_param] = payload
                    else:
                        # Simple nested replacement naive approach could be added here
                        body_data[target_param] = payload
                    req_body = json.dumps(body_data)
                except Exception as e:
                    return {"status": "error", "message": f"Failed to parse or modify JSON body: {str(e)}"}
            else:
                return {"status": "error", "message": "Unknown param_type. Use 'query' or 'json_body'.", "param_type": param_type}

            # Coroutine for the request
            async def run_req(p=payload, u=req_url, b=req_body):
                try:
                    request_kwargs = {
                        "method": method,
                        "url": u,
                        "headers": target_headers,
                    }
                    if b is not None:
                        request_kwargs["data"] = b

                    resp = await client.request(**request_kwargs)

                    status = resp.status_code
                    content_len = len(resp.content) if resp.content else 0

                    # Anomaly detection heuristics
                    if status >= 500:
                        return {
                            "payload": p,
                            "anomaly": "Server Error (5xx)",
                            "status": status,
                        }
                    if status != baseline_status:
                        return {
                            "payload": p,
                            "anomaly": (f"Status Code Deviation ({baseline_status} -> {status})"),
                            "status": status,
                        }

                    # Length deviation by > 20%
                    if baseline_len > 0:
                        diff_ratio = abs(content_len - baseline_len) / baseline_len
                        if diff_ratio > 0.2:
                            return {
                                "payload": p,
                                "anomaly": "Content Length Deviation (>20%)",
                                "status": status,
                                "len": content_len,
                            }
                    return None
                except Exception as e:
                    return {
                        "payload": p,
                        "anomaly": f"Request Failed: {str(e)}",
                    }

            tasks.append(run_req())

        # Run concurrently
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                anomalies.append(r)

    if not anomalies:
        return {
            "status": "ok",
            "message": "Fuzzing complete, No significant anomalies detected.",
            "baseline_status": baseline_status,
            "baseline_len": baseline_len,
            "anomalies": [],
        }

    return {
            "baseline_status": baseline_status,
            "baseline_len": baseline_len,
            "anomalies": anomalies,
        }


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True))
async def replay_flow(
    flow_id: str,
    method: str = None,
    headers_json: str = None,
    body: str = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Replay a captured flow, optionally with modified method, headers, or body.
    Supports session variable injection (e.g., $token) in headers and body.
    """

    # Resolve templates in headers and body if we have variables
    resolved_headers_json = headers_json
    resolved_body = body

    # Treat the sentinel value "__omit__" as no body
    if resolved_body == "__omit__":
        resolved_body = None

    if controller.session_variables:
        if resolved_headers_json:
            resolved_headers_json = _resolve_template(
                resolved_headers_json, controller.session_variables
            )
        if resolved_body:
            resolved_body = _resolve_template(resolved_body, controller.session_variables)

    parsed_headers = None
    if resolved_headers_json:
        try:
            parsed_headers = json.loads(resolved_headers_json)
        except json.JSONDecodeError:
            return {"status": "error", "message": "The headers_json parameter needs to be valid JSON."}

    msg = await controller.replay_request(
        flow_id,
        method,
        parsed_headers,
        resolved_body,
        timeout,
    )
    if msg.startswith("Replayed successfully"):
        return {"status": "ok", "message": msg, "flow_id": flow_id}
    elif "Couldn't find" in msg or "That didn't work" in msg:
        return {"status": "error", "message": msg, "flow_id": flow_id}
    else:
        return {"status": "ok", "message": msg, "flow_id": flow_id}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
async def add_interception_rule(
    rule_id: str,
    action_type: str,
    url_pattern: str = ".*",
    method: str = None,
    key: str = None,
    value: str = None,
    search_pattern: str = None,
    phase: str = "request",
) -> dict[str, Any]:
    if phase not in ["request", "response"]:
        return {"status": "error", "message": "Phase needs to be either 'request' or 'response'"}

    try:
        rule = InterceptionRule(
            id=rule_id,
            url_pattern=url_pattern,
            method=method,
            resource_type=phase,  # type: ignore
            action_type=action_type,  # type: ignore
            key=key,
            value=value,
            search_pattern=search_pattern,
        )
    except Exception as e:
        return {"status": "error", "message": f"Invalid rule parameters: {str(e)}"}

    if not controller.interceptor.add_rule(rule):
        return {"status": "error", "message": f"Invalid or unsupported regex for rule '{rule_id}'"}
    return {"status": "ok", "message": f"Added rule '{rule_id}'", "rule_id": rule_id}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def list_rules() -> dict[str, Any]:
    rules_dict = {
        rid: {
            "action": r.action_type,
            "url_pattern": r.url_pattern,
            "phase": r.resource_type,
        }
        for rid, r in controller.interceptor.rules.items()
    }
    return rules_dict


@mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False))
async def clear_rules() -> dict[str, Any]:
    controller.interceptor.clear_rules()
    return {"status": "ok", "message": "Cleared all interception rules."}


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def proxy_status() -> dict[str, Any]:
    """Return current proxy/server status."""
    # uptime calculation is monotonic and cheap
    uptime_seconds: Optional[float] = None
    if controller.running and controller.started_at is not None:
        try:
            uptime_seconds = time.monotonic() - controller.started_at
        except Exception:
            uptime_seconds = None

    # flow_count via direct COUNT(*) — cheap, no full scan of bodies
    try:
        with controller.recorder.db._get_conn() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM flows")
            row = cursor.fetchone()
            flow_count = int(row[0]) if row else 0
    except Exception:
        flow_count = 0

    db_path = getattr(controller.recorder.db, "db_path", "mitm_mcp_traffic.db")
    try:
        if os.path.exists(db_path):
            db_size_bytes = os.path.getsize(db_path)
        else:
            db_size_bytes = 0
    except Exception:
        db_size_bytes = None

    # host/port: current values (host tracked on start, port updated on start)
    host = getattr(controller, "host", controller.default_host)
    port = getattr(controller, "port", controller.default_port)

    return {
        "running": bool(controller.running),
        "host": host,
        "port": port,
        "uptime_seconds": uptime_seconds,
        "flow_count": flow_count,
        "db_path": str(db_path),
        "db_size_bytes": db_size_bytes,
        "active_rules_count": len(controller.interceptor.rules),
        "scope_domains": list(controller.scope_config.allowed_domains),
        "upstream_proxy": controller.cli_upstream_proxy,
        "auto_start": bool(controller.auto_start),
        "default_host": controller.default_host,
        "default_port": controller.default_port,
    }


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def list_tools() -> list[dict[str, Any]]:
    """List all available tools with their descriptions."""
    tools = await mcp.list_tools()
    tool_list = []
    for tool in tools:
        tool_list.append(
            {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}
        )
    return tool_list


# --- API Analysis Tools (Updated for Dicts) ---


def _normalize_path(path: str) -> Tuple[str, List[str]]:
    segments = path.split("/")
    normalized = []
    params = []

    for seg in segments:
        if not seg:
            normalized.append("")
            continue
        if re.match(r"^\d+$", seg):
            normalized.append("{id}")
            params.append("id")
        elif re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}$",
            seg,
            re.I,
        ):
            normalized.append("{uuid}")
            params.append("uuid")
        elif re.match(r"^[0-9a-f]{24}$", seg, re.I):
            normalized.append("{objectId}")
            params.append("objectId")
        elif len(seg) > 20 and re.match(r"^[a-zA-Z0-9_-]+$", seg):
            normalized.append("{token}")
            params.append("token")
        else:
            normalized.append(seg)

    return "/".join(normalized), params


def _detect_content_type(headers: Dict[str, Any]) -> str:
    ct = headers.get("content-type", headers.get("Content-Type", ""))
    if "json" in ct.lower():
        return "json"
    elif "form" in ct.lower():
        return "form"
    elif "xml" in ct.lower():
        return "xml"
    elif "text" in ct.lower():
        return "text"
    return "unknown"


def _generate_openapi_spec(
    clusters: List[Dict[str, Any]],
    title: str = "Reconstructed API",
    version: str = "1.0.0",
) -> Dict[str, Any]:
    """Reconstructs an OpenAPI v3 spec from API clusters."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": title, "version": version},
        "paths": {},
    }

    for cluster in clusters:
        path = cluster["path_pattern"]
        # OpenAPI paths must start with /
        if not path.startswith("/"):
            path = "/" + path

        method = cluster["method"].lower()

        if path not in spec["paths"]:
            spec["paths"][path] = {}

        operation = {
            "summary": f"{method.upper()} {path}",
            "parameters": [],
            "responses": {},
        }

        # Add path params
        for param in cluster["path_params"]:
            operation["parameters"].append(
                {
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )

        # Add query params
        for param in cluster["query_params"]:
            operation["parameters"].append(
                {
                    "name": param,
                    "in": "query",
                    # We could guess type here, default to string
                    "schema": {"type": "string"},
                }
            )

        # Add headers as parameters if significant
        # (simplified, ignoring common browser headers already handled)

        # Responses
        for status_code, count in cluster["status_codes"].items():
            content_types = cluster["content_types"]
            # Default response description
            desc = f"Response with status {status_code}"

            resp_obj = {"description": desc}

            if content_types:
                resp_obj["content"] = {}
                for ct in content_types:
                    if ct == "json":
                        media_type = "application/json"
                    elif ct == "xml":
                        media_type = "application/xml"
                    elif ct == "form":
                        media_type = "application/x-www-form-urlencoded"
                    else:
                        media_type = "text/plain"

                    # Could be populated with inferred schema
                    resp_obj["content"][media_type] = {"schema": {"type": "object"}}

            operation["responses"][str(status_code)] = resp_obj

        spec["paths"][path][method] = operation

    return spec


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def export_openapi_spec(domain: str = None, limit: int = None) -> dict[str, Any]:
    """
    Exports captured API traffic patterns to an OpenAPI v3 JSON specification.
    Args:
        domain: Filter traffic by domain
        limit: Max number of traffic flows to analyze. None = all flows.
    """
    clusters = await get_api_patterns(domain, limit)
    # Handle legacy string case (if get_api_patterns returned JSON string in older version)
    if isinstance(clusters, str):
        clusters = json.loads(clusters)

    spec = _generate_openapi_spec(
        clusters,
        title=f"Reconstructed API - {domain if domain else 'All'}",
    )
    return spec


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def get_api_patterns(domain: str = None, limit: int = None) -> list[dict[str, Any]]:
    """
    Cluster captured traffic into endpoint patterns.
    Args:
        domain: Filter traffic by domain
        limit: Max number of flows to analyze. None = all flows.
    """
    flows = controller.recorder.get_all_for_analysis(lightweight=True)

    if domain:
        flows = [f for f in flows if domain in f["request"]["url"]]

    if limit is not None:
        flows = flows[:limit]

    endpoint_clusters: Dict[str, Dict[str, Any]] = {}

    for f in flows:
        parsed = urlparse(f["request"]["url"])
        normalized_path, path_params = _normalize_path(parsed.path)
        method = f["request"]["method"]
        key = f"{method} {normalized_path}"

        if key not in endpoint_clusters:
            endpoint_clusters[key] = {
                "method": method,
                "path_pattern": normalized_path,
                "path_params": path_params,
                "query_params": set(),
                "request_headers": Counter(),
                "response_status_codes": Counter(),
                "content_types": Counter(),
                "sample_flow_ids": [],
                "count": 0,
            }

        cluster = endpoint_clusters[key]
        cluster["count"] += 1
        cluster["sample_flow_ids"].append(f["id"])

        query_params = parse_qs(parsed.query)
        for param in query_params.keys():
            cluster["query_params"].add(param)

        skip_headers = {
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "connection",
            "content-length",
            "content-type",
        }
        for h in f["request"]["headers"]:
            if h.lower() not in skip_headers:
                cluster["request_headers"][h] += 1

        if f["response"]:
            ct_key = _detect_content_type(f["response"]["headers"])
            cluster["response_status_codes"][f["response"]["status_code"]] += 1
            cluster["content_types"][ct_key] += 1

    result = []
    for key, cluster in sorted(endpoint_clusters.items(), key=lambda x: -x[1]["count"]):
        result.append(
            {
                "endpoint": key,
                "method": cluster["method"],
                "path_pattern": cluster["path_pattern"],
                "path_params": cluster["path_params"],
                "query_params": list(cluster["query_params"]),
                "common_headers": dict(cluster["request_headers"].most_common(10)),
                "status_codes": dict(cluster["response_status_codes"]),
                "content_types": dict(cluster["content_types"]),
                "request_count": cluster["count"],
                "sample_flow_ids": cluster["sample_flow_ids"][:3],
            }
        )

    return result


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def detect_auth_pattern(flow_ids: str = None) -> dict[str, Any]:
    if flow_ids:
        target_ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
        flows = controller.recorder.get_by_ids(target_ids)
    else:
        flows = controller.recorder.get_all_for_analysis()

    auth_signals = {
        "oauth2": {"detected": False, "signals": [], "flows": []},
        "jwt": {"detected": False, "signals": [], "flows": []},
        "api_key": {"detected": False, "signals": [], "flows": []},
        "session_cookie": {"detected": False, "signals": [], "flows": []},
        "csrf": {"detected": False, "signals": [], "flows": []},
        "basic_auth": {"detected": False, "signals": [], "flows": []},
        "bearer_token": {"detected": False, "signals": [], "flows": []},
    }

    for f in flows:
        headers = f["request"]["headers"]
        path = urlparse(f["request"]["url"]).path.lower()

        auth_header = headers.get(
            "Authorization",
            headers.get("authorization", ""),
        )

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            auth_signals["bearer_token"]["detected"] = True
            auth_signals["bearer_token"]["flows"].append(f["id"])
            if token.count(".") == 2:
                auth_signals["jwt"]["detected"] = True
                auth_signals["jwt"]["signals"].append("Bearer token appears to be JWT format")
                auth_signals["jwt"]["flows"].append(f["id"])

        if auth_header.startswith("Basic "):
            auth_signals["basic_auth"]["detected"] = True
            auth_signals["basic_auth"]["flows"].append(f["id"])

        for h, v in headers.items():
            h_lower = h.lower()
            if any(k in h_lower for k in ["x-api-key", "api-key", "apikey", "x-auth-token"]):
                auth_signals["api_key"]["detected"] = True
                auth_signals["api_key"]["signals"].append(f"Header: {h}")
                auth_signals["api_key"]["flows"].append(f["id"])

        if any(p in path for p in ["/oauth", "/token", "/authorize", "/auth/callback"]):
            auth_signals["oauth2"]["detected"] = True
            auth_signals["oauth2"]["signals"].append(f"OAuth endpoint: {path}")
            auth_signals["oauth2"]["flows"].append(f["id"])

        body_text = f["request"].get("body")
        if body_text:
            if any(
                p in body_text.lower()
                for p in [
                    "grant_type=",
                    "refresh_token=",
                    "client_id=",
                ]
            ):
                auth_signals["oauth2"]["detected"] = True
                auth_signals["oauth2"]["signals"].append("OAuth2 parameters in request body")
                auth_signals["oauth2"]["flows"].append(f["id"])

        cookie_header = headers.get("Cookie", headers.get("cookie", ""))
        if cookie_header:
            cookies = cookie_header.split(";")
            for cookie in cookies:
                c_name = cookie.strip().split("=")[0].lower() if "=" in cookie else ""
                if any(s in c_name for s in ["session", "sid", "sess", "auth"]):
                    auth_signals["session_cookie"]["detected"] = True
                    auth_signals["session_cookie"]["signals"].append(f"Session cookie: {c_name}")
                    auth_signals["session_cookie"]["flows"].append(f["id"])

        for h, v in headers.items():
            h_lower = h.lower()
            if any(c in h_lower for c in ["csrf", "xsrf", "x-csrf", "x-xsrf"]):
                auth_signals["csrf"]["detected"] = True
                auth_signals["csrf"]["signals"].append(f"CSRF header: {h}")
                auth_signals["csrf"]["flows"].append(f["id"])

    for key in auth_signals:
        auth_signals[key]["flows"] = list(set(auth_signals[key]["flows"]))[:5]
        auth_signals[key]["signals"] = list(set(auth_signals[key]["signals"]))

    detected = [k for k, v in auth_signals.items() if v["detected"]]

    return {
            "detected_auth_types": detected,
            "details": auth_signals,
        }


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def generate_scraper_code(flow_ids: str, target_framework: str = "curl_cffi") -> str:
    """
    Generate executable scraper/automation code from a comma-separated list of
    flow IDs.
    Args:
        flow_ids: Comma-separated list of flow IDs to include in the script.
        target_framework: The framework to generate code for.
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    flows_data = []

    for fid in ids:
        data = controller.recorder.get_flow_detail(fid)
        if data:
            flows_data.append(data)

    if not flows_data:
        return "No valid flows found for the provided IDs."

    normalized_flows = normalize_scraper_flows(flows_data, controller.recorder)
    return render_scraper_code(target_framework, normalized_flows)


def _env_flag(name: str, default: bool = False) -> bool:
    """Parse a boolean env var (1/true/yes/on are truthy, case-insensitive)."""
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def start():
    """Entry point for running the server directly."""
    import argparse

    parser = argparse.ArgumentParser(description="mitmproxy-mcp server")
    parser.add_argument(
        "--dump-file",
        default=os.environ.get("MITMPROXY_DUMP_FILE"),
        help="Path to save raw .flow data. Prefix with + to append. "
        "Can also be set via MITMPROXY_DUMP_FILE env var.",
    )
    parser.add_argument(
        "--upstream-proxy",
        default=os.environ.get("MITMPROXY_UPSTREAM_PROXY"),
        help="Upstream proxy URL (e.g., http://user:pass@proxy:port). "
        "Can also be set via MITMPROXY_UPSTREAM_PROXY env var.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MITMPROXY_PORT", "8080")),
        help="Default proxy listen port used by start_proxy and --auto-start "
        "(default 8080). Can also be set via MITMPROXY_PORT env var.",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MITMPROXY_HOST", "127.0.0.1"),
        help="Default proxy listen host (default 127.0.0.1). "
        "Can also be set via MITMPROXY_HOST env var.",
    )
    parser.add_argument(
        "--auto-start",
        action="store_true",
        default=_env_flag("MITMPROXY_AUTO_START"),
        help="Start the proxy immediately on server startup instead of waiting "
        "for the start_proxy tool. Can also be set via MITMPROXY_AUTO_START env var.",
    )
    args, _ = parser.parse_known_args()

    global controller
    controller = MitmController(dump_file=args.dump_file)
    controller.cli_upstream_proxy = args.upstream_proxy
    # start_proxy() and --auto-start fall back to these when no port is passed,
    # so a wrapper can pin a per-agent port that the browser also targets.
    controller.default_port = args.port
    controller.default_host = args.host
    controller.auto_start = args.auto_start
    # Re-wire live flow subscription for the new controller instance
    controller.recorder.on_flow = _notify_live_flow

    mcp.run()


if __name__ == "__main__":
    start()
