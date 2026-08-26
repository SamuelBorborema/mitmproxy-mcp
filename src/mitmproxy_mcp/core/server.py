import asyncio
import base64
import contextlib
import json
import logging
import os
import sqlite3
import sys
import time
import zlib
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl
import math
import re
import re2

import structlog

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceNotFoundError
from mcp.shared.subscriptions import ResourceUpdated
from mcp.types import ToolAnnotations
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.net.http.headers import infer_content_encoding
from mitmproxy.utils import strutils
from curl_cffi.requests import AsyncSession
from jsonpath_ng import parse as parse_jsonpath
from bs4 import BeautifulSoup

from ..models import ScopeConfig, InterceptionRule
from .scope import ScopeManager
from .recorder import TrafficRecorder
from .interceptor import TrafficInterceptor
from .generation import normalize_scraper_flows, render_scraper_code
from .diff import diff_bodies, diff_headers, diff_size, diff_status, diff_timestamp

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
        if not self.running:
            return "The proxy isn't running. Start it first with start_proxy."
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


# --- Full body access helpers ---

def _parse_headers_list(raw: Optional[str]) -> List[List[str]]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [[str(k), str(v)] for k, v in parsed]
        return [[str(k), str(v)] for k, v in parsed.items()]
    except Exception:
        return []

def _mime_from_headers(headers: List[List[str]]) -> str:
    for k, v in headers:
        if k.lower() == "content-type":
            return v
    return ""

def _fetch_body_raw(flow_id: str, is_request: bool) -> Optional[Tuple[Optional[bytes], List[List[str]], str, Optional[int]]]:
    """Fetch raw bytes, headers, mimeType for a flow.
    Returns (raw_bytes, headers_list, mimeType, status_code_or_None) or None if not found.
    Handles DB primary key lookup plus live-flow fallback when raw is NULL.
    """
    headers: List[List[str]] = []
    mime_type = ""
    raw_b64: Optional[str] = None
    status_code: Optional[int] = None
    found_row = False

    # Try DB first
    try:
        with controller.recorder.db._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            if is_request:
                cursor = conn.execute(
                    "SELECT request_raw, request_body, request_headers, size FROM flows WHERE id=?",
                    (flow_id,),
                )
            else:
                cursor = conn.execute(
                    "SELECT response_raw, response_body, response_headers, status_code, size FROM flows WHERE id=?",
                    (flow_id,),
                )
            row = cursor.fetchone()
            if row is not None:
                found_row = True
                # Extract
                raw_b64 = row["request_raw"] if is_request else row["response_raw"]
                headers_raw = row["request_headers"] if is_request else row["response_headers"]
                headers = _parse_headers_list(headers_raw)
                mime_type = _mime_from_headers(headers)
                if not is_request:
                    status_code = row["status_code"]
                # Try to decode raw_b64 if present
                if raw_b64 is not None:
                    try:
                        raw_bytes = base64.b64decode(raw_b64)
                    except Exception:
                        raw_bytes = None
                    return (raw_bytes, headers, mime_type, status_code)
                # raw is None -> check if row exists but raw null => fallback to live flow
                # keep headers/mime_type/status_code but need to fetch raw from live
            else:
                # no row -> fallback to live flow entirely
                pass
    except sqlite3.OperationalError as e:
        # column missing (old DB not migrated?) -> treat as no raw, fallback to body text
        if "no such column" in str(e).lower():
            # try fallback query without raw column
            try:
                with controller.recorder.db._get_conn() as conn2:
                    conn2.row_factory = sqlite3.Row
                    if is_request:
                        cur2 = conn2.execute("SELECT request_body, request_headers FROM flows WHERE id=?", (flow_id,))
                    else:
                        cur2 = conn2.execute("SELECT response_body, response_headers, status_code FROM flows WHERE id=?", (flow_id,))
                    r2 = cur2.fetchone()
                    if r2 is not None:
                        found_row = True
                        headers_raw = r2["request_headers"] if is_request else r2["response_headers"]
                        headers = _parse_headers_list(headers_raw)
                        mime_type = _mime_from_headers(headers)
                        if not is_request:
                            status_code = r2["status_code"]
                        body_text = r2["request_body"] if is_request else r2["response_body"]
                        if body_text is not None:
                            return (body_text.encode("utf-8", "replace"), headers, mime_type, status_code)
                        # else fall through to live fallback
                    else:
                        found_row = False
            except Exception:
                pass
        else:
            raise

    # Fallback to live flow if DB row had no raw or no row at all
    live = controller.recorder.get_live_flow(flow_id)
    if live is not None:
        try:
            msg = live.request if is_request else live.response
            if msg is not None:
                # Prefer raw_content, fallback to content
                raw = getattr(msg, "raw_content", None)
                if raw is None:
                    try:
                        raw = msg.content
                    except Exception:
                        raw = None
                if raw is not None:
                    # Need headers/mime if not already from DB
                    if not headers:
                        try:
                            headers = [[k.decode("latin-1"), v.decode("latin-1")] for k, v in msg.headers.fields]
                            mime_type = _mime_from_headers(headers)
                        except Exception:
                            pass
                    if not is_request and status_code is None:
                        # live flow response status
                        try:
                            status_code = live.response.status_code if live.response else None
                        except Exception:
                            pass
                    return (raw, headers, mime_type, status_code)
        except Exception:
            pass

    # If we found DB row but raw was None and live fallback also None, try to use stored body text as fallback
    if found_row:
        # headers already parsed, try to use body text if exists
        try:
            with controller.recorder.db._get_conn() as conn3:
                conn3.row_factory = sqlite3.Row
                if is_request:
                    c3 = conn3.execute("SELECT request_body FROM flows WHERE id=?", (flow_id,))
                else:
                    c3 = conn3.execute("SELECT response_body FROM flows WHERE id=?", (flow_id,))
                r3 = c3.fetchone()
                if r3 is not None:
                    body_t = r3["request_body"] if is_request else r3["response_body"]
                    if body_t is not None:
                        return (body_t.encode("utf-8", "replace"), headers, mime_type, status_code)
                    else:
                        # empty body
                        return (b"", headers, mime_type, status_code)
        except Exception:
            pass
        # still found row, return empty bytes
        return (b"", headers, mime_type, status_code)

    # Not found anywhere
    return None

def _body_to_text(raw_bytes: Optional[bytes], mime_type: str, encoding: str) -> Tuple[str, bool, str]:
    """Convert raw_bytes to text according to encoding param.
    Returns (text, is_base64, effective_encoding)
    """
    if raw_bytes is None:
        raw_bytes = b""
    if encoding not in ("auto", "text", "base64"):
        encoding = "auto"
    effective = encoding
    is_b64 = False
    text = ""
    if encoding == "base64":
        is_b64 = True
        effective = "base64"
        text = base64.b64encode(raw_bytes).decode("ascii") if raw_bytes else ""
    elif encoding == "text":
        is_b64 = False
        effective = "text"
        enc = infer_content_encoding(mime_type, raw_bytes)
        try:
            text = raw_bytes.decode(enc, errors="replace")
        except Exception:
            text = raw_bytes.decode("utf-8", errors="replace")
    else:  # auto
        if raw_bytes and strutils.is_mostly_bin(raw_bytes):
            is_b64 = True
            effective = "base64"
            text = base64.b64encode(raw_bytes).decode("ascii")
        else:
            is_b64 = False
            effective = "text"
            enc = infer_content_encoding(mime_type, raw_bytes)
            try:
                text = raw_bytes.decode(enc, errors="replace")
            except Exception:
                text = raw_bytes.decode("utf-8", errors="replace")
    return text, is_b64, effective


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def get_request_body(flow_id: str, offset: int = 0, limit: int = 1_000_000, encoding: str = "auto") -> Dict[str, Any]:
    """Get full request body with chunked/paginated access.

    Returns full body even when it exceeds the 2000-char preview limit in inspect_flow.
    Supports pagination via offset/limit and binary detection.

    Args:
        flow_id: The ID of the captured flow
        offset: Byte/char offset to start reading from (default 0)
        limit: Max chars to return (default 1_000_000). Use pagination for large bodies.
        encoding: "auto" (default, detect via is_mostly_bin), "text" (force text via infer_content_encoding), or "base64" (force base64)

    Returns:
        Dict with flow_id, headers (ordered [[k,v],...]), mimeType, size (chunk length), total_size (full length), is_base64, encoding (effective), truncated, next_offset, text (chunk)
    """
    if encoding not in ("auto", "text", "base64"):
        return {"error": f"Invalid encoding '{encoding}'. Must be one of auto, text, base64.", "flow_id": flow_id}
    if offset < 0:
        offset = 0
    if limit < 0:
        limit = 0

    fetched = _fetch_body_raw(flow_id, is_request=True)
    if fetched is None:
        return {"error": "Couldn't find that flow.", "flow_id": flow_id}
    raw_bytes, headers, mime_type, _ = fetched
    text, is_b64, eff_enc = _body_to_text(raw_bytes, mime_type, encoding)
    total = len(text)
    # Clamp offset
    if offset > total:
        offset = total
    end = offset + limit
    chunk = text[offset:end]
    truncated = end < total
    next_off = end if truncated else None
    return {
        "flow_id": flow_id,
        "headers": headers,
        "mimeType": mime_type,
        "size": len(chunk),
        "total_size": total,
        "is_base64": is_b64,
        "encoding": eff_enc,
        "truncated": truncated,
        "next_offset": next_off,
        "text": chunk,
    }


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
async def get_response_body(flow_id: str, offset: int = 0, limit: int = 1_000_000, encoding: str = "auto") -> Dict[str, Any]:
    """Get full response body with chunked/paginated access.

    Returns full body even when it exceeds the 2000-char preview limit in inspect_flow.
    Supports pagination via offset/limit and binary detection. For binary content (e.g. PNG) returns base64 when encoding is auto.

    Args:
        flow_id: The ID of the captured flow
        offset: Char offset to start reading from (default 0)
        limit: Max chars to return (default 1_000_000). Use pagination for large bodies. Pagination is recommended for bodies larger than 1MB.
        encoding: "auto" (default, detect via is_mostly_bin), "text" (force text via infer_content_encoding), or "base64" (force base64)

    Returns:
        Dict with flow_id, headers (ordered [[k,v],...]), mimeType, status_code, size (chunk length), total_size (full length), is_base64, encoding (effective), truncated, next_offset, text (chunk). For pagination, repeatedly call with offset=next_offset until truncated is False.
    """
    if encoding not in ("auto", "text", "base64"):
        return {"error": f"Invalid encoding '{encoding}'. Must be one of auto, text, base64.", "flow_id": flow_id}
    if offset < 0:
        offset = 0
    if limit < 0:
        limit = 0

    fetched = _fetch_body_raw(flow_id, is_request=False)
    if fetched is None:
        return {"error": "Couldn't find that flow.", "flow_id": flow_id}
    raw_bytes, headers, mime_type, status_code = fetched
    text, is_b64, eff_enc = _body_to_text(raw_bytes, mime_type, encoding)
    total = len(text)
    if offset > total:
        offset = total
    end = offset + limit
    chunk = text[offset:end]
    truncated = end < total
    next_off = end if truncated else None
    return {
        "flow_id": flow_id,
        "headers": headers,
        "mimeType": mime_type,
        "status_code": status_code,
        "size": len(chunk),
        "total_size": total,
        "is_base64": is_b64,
        "encoding": eff_enc,
        "truncated": truncated,
        "next_offset": next_off,
        "text": chunk,
    }


@mcp.resource("flows://{id}/request_body", mime_type="application/octet-stream")
def flow_request_body_resource(id: str) -> str | bytes:
    """Resource for full request body: flows://{id}/request_body

    Returns the full request body for the given flow ID. Binary content is returned as bytes (served as base64 Blob), text as string. Content-Type is used to determine mime_type. For pagination use get_request_body tool with offset/limit.
    """
    fetched = _fetch_body_raw(id, is_request=True)
    if fetched is None:
        raise ResourceNotFoundError(f"Unknown resource: flows://{id}/request_body")
    raw_bytes, headers, mime_type, _ = fetched
    if raw_bytes is None:
        raw_bytes = b""
    # Auto detection for resource return type
    if raw_bytes and strutils.is_mostly_bin(raw_bytes):
        return raw_bytes
    # text
    enc = infer_content_encoding(mime_type, raw_bytes)
    try:
        return raw_bytes.decode(enc, errors="replace")
    except Exception:
        return raw_bytes.decode("utf-8", errors="replace")


@mcp.resource("flows://{id}/response_body", mime_type="application/octet-stream")
def flow_response_body_resource(id: str) -> str | bytes:
    """Resource for full response body: flows://{id}/response_body

    Returns the full response body for the given flow ID. Binary content is returned as bytes (served as base64 Blob), text as string. Content-Type determines decoding. For pagination use get_response_body tool with offset/limit.
    """
    fetched = _fetch_body_raw(id, is_request=False)
    if fetched is None:
        raise ResourceNotFoundError(f"Unknown resource: flows://{id}/response_body")
    raw_bytes, headers, mime_type, _ = fetched
    if raw_bytes is None:
        raw_bytes = b""
    if raw_bytes and strutils.is_mostly_bin(raw_bytes):
        return raw_bytes
    enc = infer_content_encoding(mime_type, raw_bytes)
    try:
        return raw_bytes.decode(enc, errors="replace")
    except Exception:
        return raw_bytes.decode("utf-8", errors="replace")


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
async def export_har(
    file_path: str,
    flow_ids: str = None,
    domain: str = None,
    limit: int = None,
    compress: bool = False,
) -> dict[str, Any]:
    """
    Export captured traffic to HAR (HTTP Archive) format for use with Burp Suite, Postman, or browser devtools.

    Defaults to all captured flows — use domain/limit/flow_ids to scope, otherwise large DB produces large HAR. Filterable.

    Args:
        file_path: Relative path (within project cwd) to write the HAR file. Supports .har, .zhar (compressed), and .json extensions. Must be under Path.cwd(). Parent directories are created automatically.
        flow_ids: Comma-separated list of flow IDs to export. If provided, only those flows are exported (via get_by_ids).
        domain: Substring filter on URL (like get_api_patterns). Only flows whose URL contains this string are exported.
        limit: Max number of flows to export, ordered by timestamp DESC. None = no limit.
        compress: If True, compress output with zlib (level 9). Also auto-enabled for .zhar extension.

    Returns:
        Dict with status, path, entries, bytes, and filter info. On security violation returns {"status":"error","message":"Security Error..."}.
    """
    # Security: Prevent path traversal and restrict to working directory
    try:
        requested_path = Path(file_path).resolve()
        base_dir = Path.cwd().resolve()
        if not str(requested_path).startswith(str(base_dir) + os.sep) and str(requested_path) != str(base_dir):
            return {
                "status": "error",
                "message": f"Security Error: Access denied to {file_path}. Path must be within the project directory.",
            }
    except Exception as e:
        return {"status": "error", "message": f"Invalid path: {str(e)}"}

    # Validate extension and ensure parent
    allowed_exts = (".har", ".zhar", ".json")
    if not str(requested_path).lower().endswith(allowed_exts):
        return {
            "status": "error",
            "message": f"Unsupported file extension: {requested_path.suffix}. Allowed: .har, .zhar, .json",
        }
    try:
        requested_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {"status": "error", "message": f"Failed to create parent directory: {str(e)}"}

    should_compress = bool(compress) or str(requested_path).lower().endswith(".zhar")

    try:
        db = controller.recorder.db

        # Detect optional raw columns for fidelity (parallel migration)
        has_raw = False
        try:
            with db._get_conn() as conn:
                cursor = conn.execute("PRAGMA table_info(flows)")
                cols = [r[1] for r in cursor.fetchall()]
                if "request_raw" in cols and "response_raw" in cols:
                    has_raw = True
                elif "request_raw" in cols or "response_raw" in cols:
                    has_raw = True
        except Exception:
            has_raw = False

        # Build SELECT
        select_cols = "id, url, method, status_code, request_headers, request_body, response_headers, response_body, timestamp"
        if has_raw:
            # Check which raw cols actually exist to avoid SELECT errors
            try:
                with db._get_conn() as conn:
                    cursor = conn.execute("PRAGMA table_info(flows)")
                    existing = {r[1] for r in cursor.fetchall()}
                    raw_to_add = []
                    if "request_raw" in existing:
                        raw_to_add.append("request_raw")
                    if "response_raw" in existing:
                        raw_to_add.append("response_raw")
                    if raw_to_add:
                        select_cols += ", " + ", ".join(raw_to_add)
                    else:
                        has_raw = False
            except Exception:
                has_raw = False

        sql = f"SELECT {select_cols} FROM flows"
        params: List[Any] = []
        clauses: List[str] = []

        ids: Optional[List[str]] = None
        if flow_ids is not None:
            # csv → get_by_ids semantics
            ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
            if ids:
                placeholders = ",".join(["?"] * len(ids))
                clauses.append(f"id IN ({placeholders})")
                params.extend(ids)
            else:
                # No valid ids -> return empty HAR
                sql += " WHERE 1=0"
                clauses = []  # avoid double WHERE
                params = []
                # Skip further clauses, go directly to fetch
                with db._get_conn() as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(sql, params)
                    rows = cursor.fetchall()
                # Proceed to HAR generation with empty rows
                rows_for_empty = rows
                # Generate empty HAR
                from mitmproxy.addons.savehar import SaveHar

                s = SaveHar()
                har_empty = s.make_har([])
                data_empty = json.dumps(har_empty, indent=2).encode()
                if should_compress:
                    data_empty = zlib.compress(data_empty, 9)

                def _write_empty():
                    with open(requested_path, "wb") as f:
                        f.write(data_empty)

                await asyncio.to_thread(_write_empty)
                return {
                    "status": "ok",
                    "path": str(requested_path),
                    "entries": 0,
                    "bytes": len(data_empty),
                    "filter": {"domain": domain, "limit": limit},
                }

        if domain:
            clauses.append("url LIKE ?")
            params.append(f"%{domain}%")

        if clauses:
            # If we already handled empty ids case, clauses may be non-empty but sql already has WHERE from that branch.
            # For normal path, add WHERE
            if "WHERE 1=0" not in sql:
                sql += " WHERE " + " AND ".join(clauses)

        sql += " ORDER BY timestamp DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        # Fetch rows
        with db._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()
            except sqlite3.OperationalError as e:
                # Fallback if raw columns missing (should not happen after PRAGMA check, but tolerate)
                if "request_raw" in str(e) or "response_raw" in str(e):
                    # Retry without raw columns
                    select_cols_fallback = "id, url, method, status_code, request_headers, request_body, response_headers, response_body, timestamp"
                    sql_fallback = sql.replace(select_cols, select_cols_fallback)
                    cursor = conn.execute(sql_fallback, params)
                    rows = cursor.fetchall()
                    has_raw = False
                else:
                    raise

        # Reconstruct flows for SaveHar
        flows: List[Any] = []
        # Import here to avoid circular
        from mitmproxy import connection as mitm_connection
        from mitmproxy import http as mitm_http

        # Use recorder helper if available, else local fallback
        try:
            from .recorder import _parse_headers_ordered as parse_ordered  # type: ignore
        except Exception:
            def parse_ordered(raw: str):  # type: ignore
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return parsed
                return [[k, v] for k, v in parsed.items()]

        for row in rows:
            try:
                url = row["url"] or ""
                method = row["method"] or "GET"
                timestamp = row["timestamp"] if row["timestamp"] is not None else time.time()

                # Request headers
                raw_req_headers = row["request_headers"]
                ordered_req: List[List[str]] = []
                if raw_req_headers:
                    try:
                        ordered_req = parse_ordered(raw_req_headers)
                    except Exception:
                        try:
                            parsed = json.loads(raw_req_headers)
                            if isinstance(parsed, list):
                                ordered_req = parsed
                            else:
                                ordered_req = [[k, v] for k, v in parsed.items()]
                        except Exception:
                            ordered_req = []
                try:
                    req_headers = mitm_http.Headers(
                        [[k.encode("latin-1"), v.encode("latin-1")] for k, v in ordered_req]
                    )
                except Exception:
                    req_headers = mitm_http.Headers()

                # Request content
                req_content: bytes = b""
                # Prefer raw base64 if available
                raw_val = None
                try:
                    raw_val = row["request_raw"] if has_raw and "request_raw" in row.keys() else None
                except Exception:
                    raw_val = None
                if raw_val is not None:
                    try:
                        req_content = base64.b64decode(raw_val)
                    except Exception:
                        body_text = row["request_body"]
                        req_content = body_text.encode("utf-8", "surrogateescape") if body_text else b""
                else:
                    body_text = row["request_body"]
                    req_content = body_text.encode("utf-8", "surrogateescape") if body_text else b""

                request = mitm_http.Request.make(method, url, content=req_content, headers=req_headers)
                request.timestamp_start = timestamp
                request.timestamp_end = timestamp
                request.http_version = "HTTP/1.1"

                # Response
                response = None
                status_code = row["status_code"]
                if status_code is not None:
                    raw_resp_headers = row["response_headers"]
                    ordered_resp: List[List[str]] = []
                    if raw_resp_headers:
                        try:
                            ordered_resp = parse_ordered(raw_resp_headers)
                        except Exception:
                            try:
                                parsed = json.loads(raw_resp_headers)
                                if isinstance(parsed, list):
                                    ordered_resp = parsed
                                else:
                                    ordered_resp = [[k, v] for k, v in parsed.items()]
                            except Exception:
                                ordered_resp = []
                    try:
                        resp_headers = mitm_http.Headers(
                            [[k.encode("latin-1"), v.encode("latin-1")] for k, v in ordered_resp]
                        )
                    except Exception:
                        resp_headers = mitm_http.Headers()

                    resp_content: bytes = b""
                    raw_resp_val = None
                    try:
                        raw_resp_val = row["response_raw"] if has_raw and "response_raw" in row.keys() else None
                    except Exception:
                        raw_resp_val = None
                    if raw_resp_val is not None:
                        try:
                            resp_content = base64.b64decode(raw_resp_val)
                        except Exception:
                            body_text = row["response_body"]
                            resp_content = body_text.encode("utf-8", "surrogateescape") if body_text else b""
                    else:
                        body_text = row["response_body"]
                        resp_content = body_text.encode("utf-8", "surrogateescape") if body_text else b""

                    try:
                        response = mitm_http.Response.make(int(status_code), content=resp_content, headers=resp_headers)
                    except Exception:
                        response = mitm_http.Response.make(int(status_code), content=resp_content, headers=resp_headers)
                    response.timestamp_start = timestamp
                    response.timestamp_end = timestamp
                    response.http_version = "HTTP/1.1"

                # Build flow with dummy connections
                parsed_url = urlparse(url)
                host = parsed_url.hostname or "example.com"
                try:
                    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                except Exception:
                    port = 80

                client_conn = mitm_connection.Client(
                    peername=("127.0.0.1", 0),
                    sockname=("127.0.0.1", 0),
                    timestamp_start=timestamp,
                )
                server_conn = mitm_connection.Server(address=(host, port))
                flow = mitm_http.HTTPFlow(client_conn, server_conn, live=False)
                flow.request = request
                if response is not None:
                    flow.response = response
                # Preserve original ID for traceability
                try:
                    flow.id = row["id"]
                except Exception:
                    pass
                flows.append(flow)
            except Exception as e:
                # Skip problematic flow but log
                print(f"Skipping flow during HAR export: {e}", file=sys.stderr)
                continue

        from mitmproxy.addons.savehar import SaveHar

        s = SaveHar()
        har = s.make_har(flows)
        data = json.dumps(har, indent=2).encode()
        if should_compress:
            data = zlib.compress(data, 9)

        def _write():
            with open(requested_path, "wb") as f:
                f.write(data)

        await asyncio.to_thread(_write)

        return {
            "status": "ok",
            "path": str(requested_path),
            "entries": len(har["log"]["entries"]),
            "bytes": len(data),
            "filter": {"domain": domain, "limit": limit},
        }
    except Exception as e:
        logger.error("export_har_failed", error=str(e))
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
    elif "Couldn't find" in msg or "That didn't work" in msg or "isn't running" in msg:
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
    """Return current proxy/server status. Includes flow duration (time between request start and response end) stored per flow in the DB."""
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
async def diff_flows(
    flow_ids: str,
    compare: str = "all",
    body_diff_mode: str = "auto",
    context_lines: int = 5,
    max_body_chars: int = 20000,
    include_headers: bool = True,
) -> dict[str, Any]:
    """Diff n flows (mesh) anchored to first, read-only.

    Args:
        flow_ids: Comma-separated list of flow IDs (at least 2). Anchor is first.
        compare: What to compare – all|request|response|headers|body|status.
        body_diff_mode: How to diff bodies – auto|text|json|hex|none.
        context_lines: Unified diff context lines.
        max_body_chars: Guard for large bodies – sha256 + truncated preview.
        include_headers: Whether to include header diffs.
    """
    allowed_compare = {"all", "request", "response", "headers", "body", "status"}
    allowed_modes = {"auto", "text", "json", "hex", "none"}

    # Validate compare / mode
    if compare not in allowed_compare:
        return {"error": f"Invalid compare value '{compare}'. Allowed: {sorted(allowed_compare)}"}
    if body_diff_mode not in allowed_modes:
        return {"error": f"Invalid body_diff_mode '{body_diff_mode}'. Allowed: {sorted(allowed_modes)}"}

    # Parse ids
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    if len(ids) < 2:
        return {"error": "Need at least 2 flow IDs", "flows": ids, "compare": compare}

    # Clamp context/max chars
    if context_lines < 0:
        context_lines = 5
    if max_body_chars <= 0:
        max_body_chars = 20000

    # Fetch flows – ordered_headers True to preserve multiset and order
    try:
        fetched = controller.recorder.get_by_ids(ids, ordered_headers=True)
    except Exception as e:
        return {"error": f"Failed to fetch flows: {str(e)}", "flows": ids}

    # Map by id and reorder to input order, detect missing
    by_id = {f["id"]: f for f in fetched}
    missing = [fid for fid in ids if fid not in by_id]
    if missing:
        return {"error": f"Flows not found: {missing}", "flows": ids, "missing": missing, "found": list(by_id.keys())}

    ordered = [by_id[fid] for fid in ids]
    anchor = ordered[0]
    anchor_id = anchor["id"]

    # Helpers to extract content-type
    def _content_type(headers) -> Optional[str]:
        if not headers:
            return None
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.lower() == "content-type":
                    return v
            return None
        # list of [k,v]
        for kv in headers:
            if len(kv) >= 2 and str(kv[0]).lower() == "content-type":
                return str(kv[1])
        return None

    def _extract(flow: dict[str, Any]) -> dict[str, Any]:
        req = flow.get("request") or {}
        resp = flow.get("response")
        return {
            "req_url": req.get("url"),
            "req_method": req.get("method"),
            "req_headers": req.get("headers"),
            "req_body": req.get("body"),
            "resp_status": resp.get("status_code") if resp else None,
            "resp_headers": resp.get("headers") if resp else None,
            "resp_body": resp.get("body") if resp else None,
            "timestamp": flow.get("timestamp"),
            "size": flow.get("size"),
            "content_type_req": _content_type(req.get("headers")),
            "content_type_resp": _content_type(resp.get("headers") if resp else None),
        }

    anchor_ex = _extract(anchor)
    warnings: List[str] = []

    diffs: List[Dict[str, Any]] = []

    # Pre-compute anchor vs each other
    for idx in range(1, len(ordered)):
        other = ordered[idx]
        other_ex = _extract(other)
        other_id = other["id"]

        # Basic status/size/timestamp diffs
        status_diff = diff_status(anchor_ex["resp_status"], other_ex["resp_status"])
        size_diff = diff_size(anchor_ex["size"], other_ex["size"])
        ts_delta = diff_timestamp(anchor_ex["timestamp"], other_ex["timestamp"])

        entry: Dict[str, Any] = {
            "flow_id": other_id,
            "anchor_id": anchor_id,
            "status": status_diff,
            "size": size_diff,
            "timestamp_delta_seconds": ts_delta,
        }

        # Decide which sections to include based on compare
        include_request = compare in ("all", "request", "headers", "body")
        include_response = compare in ("all", "response", "headers", "body", "status")
        # status already included; filter per compare if needed
        if compare == "status":
            include_request = False
            include_response = False
            # keep status/size/timestamp only
            # but still allow top-level status/size
        elif compare == "headers":
            include_request = True
            include_response = True
        elif compare == "body":
            include_request = True
            include_response = True
        elif compare == "request":
            include_response = False
        elif compare == "response":
            include_request = False

        # Request section
        if include_request or compare == "all":
            req_section: Dict[str, Any] = {}
            # url/method diffs
            req_section["url"] = {
                "a": anchor_ex["req_url"],
                "b": other_ex["req_url"],
                "diff": anchor_ex["req_url"] != other_ex["req_url"],
            }
            req_section["method"] = {
                "a": anchor_ex["req_method"],
                "b": other_ex["req_method"],
                "diff": anchor_ex["req_method"] != other_ex["req_method"],
            }
            if compare in ("all", "request", "headers"):
                if include_headers:
                    hdr_diff = diff_headers(anchor_ex["req_headers"], other_ex["req_headers"])
                    req_section["headers"] = hdr_diff
                else:
                    req_section["headers"] = {"skipped": True, "reason": "include_headers=False"}
            # body diff
            if compare in ("all", "request", "body"):
                body_mode = body_diff_mode if compare != "headers" else "none"
                if compare == "headers":
                    body_mode = "none"
                # For compare=status, skip body
                if compare == "status":
                    req_section["body"] = {"diff_type": "none", "note": "skipped for compare=status"}
                else:
                    bdiff = diff_bodies(
                        anchor_ex["req_body"],
                        other_ex["req_body"],
                        mode=body_mode,
                        max_body_chars=max_body_chars,
                        context_lines=context_lines,
                        content_type_a=anchor_ex["content_type_req"],
                        content_type_b=other_ex["content_type_req"],
                        size_a=anchor_ex["size"],
                        size_b=other_ex["size"],
                    )
                    req_section["body"] = bdiff
                    if bdiff.get("warnings"):
                        warnings.extend([f"request body {other_id}: {w}" for w in bdiff["warnings"]])
                    if bdiff.get("truncated"):
                        warnings.append(f"request body truncated for {anchor_id} vs {other_id}")
            entry["request"] = req_section

        # Response section
        if include_response or compare == "all":
            resp_section: Dict[str, Any] = {}
            # status already at top, but also include in response
            if compare in ("all", "response", "status"):
                resp_section["status"] = status_diff
            if compare in ("all", "response", "headers"):
                if include_headers:
                    hdr_diff = diff_headers(anchor_ex["resp_headers"], other_ex["resp_headers"])
                    resp_section["headers"] = hdr_diff
                else:
                    resp_section["headers"] = {"skipped": True, "reason": "include_headers=False"}
            if compare in ("all", "response", "body"):
                # For headers/status compare, skip body
                if compare in ("headers", "status"):
                    resp_section["body"] = {"diff_type": "none", "note": f"skipped for compare={compare}"}
                else:
                    bdiff = diff_bodies(
                        anchor_ex["resp_body"],
                        other_ex["resp_body"],
                        mode=body_diff_mode,
                        max_body_chars=max_body_chars,
                        context_lines=context_lines,
                        content_type_a=anchor_ex["content_type_resp"],
                        content_type_b=other_ex["content_type_resp"],
                        size_a=anchor_ex["size"],
                        size_b=other_ex["size"],
                    )
                    resp_section["body"] = bdiff
                    if bdiff.get("warnings"):
                        warnings.extend([f"response body {other_id}: {w}" for w in bdiff["warnings"]])
                    if bdiff.get("truncated"):
                        warnings.append(f"response body truncated for {anchor_id} vs {other_id}")
                    # binary vs text warning
                    if bdiff.get("binary") and bdiff.get("diff_type") == "text":
                        warnings.append(f"binary response body diffed as text for {other_id}")
            # size already at top, but also include in response if needed
            if compare in ("all", "response"):
                resp_section["size"] = size_diff
            if resp_section:
                entry["response"] = resp_section

        # If compare filtering removed both request/response, ensure at least status/size remain
        if compare == "status":
            # already have status/size/timestamp, no need for request/response
            pass
        elif compare == "headers":
            # ensure headers diff is present, body skipped
            pass

        diffs.append(entry)

    # Build full matrix (n x n) for mesh
    n = len(ordered)
    matrix: List[List[Optional[Dict[str, Any]]]] = []
    for i in range(n):
        row: List[Optional[Dict[str, Any]]] = []
        for j in range(n):
            if i == j:
                row.append(None)
                continue
            a = ordered[i]
            b = ordered[j]
            a_ex = _extract(a)
            b_ex = _extract(b)
            cell: Dict[str, Any] = {
                "flow_a": a["id"],
                "flow_b": b["id"],
                "status": diff_status(a_ex["resp_status"], b_ex["resp_status"]),
                "size": diff_size(a_ex["size"], b_ex["size"]),
                "timestamp_delta_seconds": diff_timestamp(a_ex["timestamp"], b_ex["timestamp"]),
            }
            # Add lightweight url/method diff for matrix
            cell["url_diff"] = a_ex["req_url"] != b_ex["req_url"]
            cell["method_diff"] = a_ex["req_method"] != b_ex["req_method"]
            # For feasibility, we don't compute full body diffs in matrix to avoid O(n^2) large diffs
            # But include header diff counts if include_headers and compare allows
            if include_headers and compare in ("all", "headers"):
                hdr = diff_headers(a_ex["req_headers"], b_ex["req_headers"])
                cell["request_headers_changed"] = bool(hdr["added"] or hdr["removed"] or hdr["modified"])
            row.append(cell)
        matrix.append(row)

    # Deduplicate warnings while preserving order
    seen = set()
    uniq_warnings: List[str] = []
    for w in warnings:
        if w not in seen:
            seen.add(w)
            uniq_warnings.append(w)

    result: Dict[str, Any] = {
        "flows": ids,
        "anchor": anchor_id,
        "diffs": diffs,
        "matrix": matrix,
        "warnings": uniq_warnings,
        "compare": compare,
        "body_diff_mode": body_diff_mode,
        "include_headers": include_headers,
        "context_lines": context_lines,
        "max_body_chars": max_body_chars,
    }

    # If no warnings, keep empty list (spec expects warnings key)
    return result


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


def _anomaly_quartiles(values: List[float], sensitivity: float = 1.5) -> Dict[str, float]:
    """Pure python quartiles / IQR (sorted, no numpy). Returns q1,q3,median,iqr,lower,upper."""
    if not values:
        return {"q1": 0.0, "q3": 0.0, "median": 0.0, "iqr": 0.0, "lower": 0.0, "upper": 0.0}
    # Prefer shared helper in TrafficDB if available
    try:
        # Use recorder's helper for consistency
        return controller.recorder.db.get_cluster_stats(values, sensitivity)  # type: ignore
    except Exception:
        pass
    s = sorted(values)
    n = len(s)

    def _pct(p: float) -> float:
        if n == 1:
            return float(s[0])
        k = (n - 1) * p / 100.0
        f = int(math.floor(k))
        c = int(math.ceil(k))
        if f == c:
            return float(s[int(k)])
        d = k - f
        if c >= n:
            c = n - 1
        if f >= n:
            f = n - 1
        return float(s[f]) * (1 - d) + float(s[c]) * d

    q1 = _pct(25)
    q3 = _pct(75)
    median = _pct(50)
    iqr = q3 - q1
    lower = q1 - sensitivity * iqr
    upper = q3 + sensitivity * iqr
    return {"q1": q1, "q3": q3, "median": median, "iqr": iqr, "lower": lower, "upper": upper}


def _p95_value(values: List[float]) -> Optional[float]:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    if n == 1:
        return float(s[0])
    # Interpolate like quartiles (pure python, no numpy)
    k = (n - 1) * 0.95
    f = int(math.floor(k))
    c = int(math.ceil(k))
    if f == c:
        return float(s[int(k)])
    d = k - f
    if c >= n:
        c = n - 1
    if f >= n:
        f = n - 1
    return float(s[f]) * (1 - d) + float(s[c]) * d


@mcp.tool(annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False))
async def detect_anomalies(
    domain: str = None,
    method: str = None,
    limit: int = None,
    sensitivity: float = 1.5,
    min_cluster: int = 5,
) -> Dict[str, Any]:
    """Detect anomalous flows via per-endpoint clustering.

    Clustering reuses `_normalize_path` logic (numeric→{id}, uuid→{uuid},
    24hex→{objectId}, token>20→{token}) and `method + normalized_path` as key,
    like `get_api_patterns`.

    Signals (from existing DB columns, no migration yet):
    - `size` quartiles (pure python sorted q1/q3, IQR*sensitivity)
    - `status_code` not in mode where mode freq >0.8
    - `content_type` shift (via `_detect_content_type`)
    - `timestamp` inter-arrival gap >p95
    - `request_body` length outlier (IQR)
    - JSON key-count outlier (json.loads full body, IQR)

    Tunability: `sensitivity` is the IQR multiplier (default 1.5, lower is more
    sensitive, higher reduces flags). `min_cluster` is the minimum flows per
    endpoint cluster to apply per-cluster IQR (default 5); smaller clusters use
    global fallback z>3 or are skipped.

    Future-ready: If a `duration` column exists (parallel feat/full-body-access),
    TTFB outlier via duration IQR is also flagged. Missing column is tolerated.

    Returns:
        {clusters:[{endpoint, count, median_size, q1, q3, mode_status, sample_flow_ids}],
         anomalies:[{flow_id, endpoint, signals:[...], scores:{iqr,z,status_rarity}, explanation}],
         total_flows, clusters_count}
        Sorted by composite score.
    """
    # --- Fetch flows (with large-DB optimization: lightweight first) ---
    # Decide optimization based on total row count
    try:
        with controller.recorder.db._get_conn() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM flows")
            row = cur.fetchone()
            total_in_db = int(row[0]) if row else 0
    except Exception:
        total_in_db = 0

    # Use lightweight optimization for large DBs to reduce memory
    use_lightweight_opt = total_in_db > 1000

    if use_lightweight_opt:
        # Lightweight first (no bodies) for clustering
        try:
            flows_light = controller.recorder.get_all_for_analysis(lightweight=True, limit=None)
        except Exception:
            flows_light = controller.recorder.get_all_for_analysis(lightweight=False, limit=None)
            use_lightweight_opt = False
            flows = flows_light
        else:
            flows = flows_light
            # Apply filters
            if domain:
                flows = [f for f in flows if domain in f["request"]["url"]]
            if method:
                flows = [f for f in flows if f["request"]["method"].upper() == method.upper()]
            if limit is not None:
                flows = flows[:limit]
            # For lightweight mode we will flag candidates via size/status/timestamp/content_type
            # Body-related signals will be evaluated in second-pass for flagged candidates only.
            lightweight_mode = True
    else:
        lightweight_mode = False

    if not use_lightweight_opt:
        # Standard path: fetch full flows
        try:
            flows_full = controller.recorder.get_all_for_analysis(lightweight=False, limit=None)
        except Exception:
            flows_full = []
        flows = flows_full
        if domain:
            flows = [f for f in flows if domain in f["request"]["url"]]
        if method:
            flows = [f for f in flows if f["request"]["method"].upper() == method.upper()]
        if limit is not None:
            flows = flows[:limit]
        lightweight_mode = False

    total_flows = len(flows)
    if total_flows == 0:
        return {"clusters": [], "anomalies": [], "total_flows": 0, "clusters_count": 0}

    # For lightweight optimization we may need to second-pass fetch bodies for anomaly candidates later.
    # Keep a map of id -> flow for quick lookup after second-pass
    flow_by_id: Dict[str, Dict[str, Any]] = {f["id"]: f for f in flows}

    # --- Clustering via _normalize_path ---
    clusters: Dict[str, Dict[str, Any]] = {}
    for f in flows:
        try:
            parsed = urlparse(f["request"]["url"])
            norm_path, _params = _normalize_path(parsed.path)
        except Exception:
            norm_path = f["request"].get("url", "")
        m = f["request"]["method"]
        key = f"{m} {norm_path}"
        if key not in clusters:
            clusters[key] = {
                "endpoint": key,
                "method": m,
                "path_pattern": norm_path,
                "count": 0,
                "flows": [],
                "sizes": [],
                "timestamps": [],
                "statuses": [],
                "content_types": [],
                "body_lengths": [],
                "json_key_counts": [],
                "durations": [],
                "sample_flow_ids": [],
            }
        c = clusters[key]
        c["count"] += 1
        c["flows"].append(f)
        c["sample_flow_ids"].append(f["id"])

        # size (top-level, fallback to 0)
        sz = f.get("size")
        if sz is None:
            # Fallback: try len of response body if present
            try:
                rb = f["response"]["body"] if f.get("response") and f["response"].get("body") else ""
                sz = len(rb) if isinstance(rb, (str, bytes)) else 0
            except Exception:
                sz = 0
        try:
            sz = int(sz)
        except Exception:
            sz = 0
        c["sizes"].append(float(sz))
        f["_size"] = float(sz)

        # timestamp
        ts = f.get("timestamp")
        if ts is not None:
            try:
                tsf = float(ts)
                c["timestamps"].append(tsf)
                f["_timestamp"] = tsf
            except Exception:
                f["_timestamp"] = None
        else:
            f["_timestamp"] = None

        # status_code
        status = None
        try:
            if f.get("response"):
                status = f["response"].get("status_code")
        except Exception:
            status = None
        if status is not None:
            c["statuses"].append(status)
        f["_status"] = status

        # content_type via _detect_content_type
        ct = "unknown"
        try:
            if f.get("response") and f["response"].get("headers"):
                # _detect_content_type expects dict with content-type keys
                hdrs = f["response"]["headers"]
                # hdrs may be dict or list; normalize to dict lower
                if isinstance(hdrs, list):
                    hdrs = {k: v for k, v in hdrs}
                low_hdrs = {k.lower(): v for k, v in hdrs.items()} if isinstance(hdrs, dict) else {}
                ct = _detect_content_type(low_hdrs)
            elif f.get("response") and f["response"].get("headers") is None:
                ct = "unknown"
        except Exception:
            ct = "unknown"
        c["content_types"].append(ct)
        f["_content_type"] = ct

        # request_body length and json key count (full body, lightweight may lack)
        req_body = f["request"].get("body") if isinstance(f.get("request"), dict) else None
        # lightweight mode has no body key
        if req_body is None and not lightweight_mode:
            # Try to fetch via body key elsewhere? already None
            pass
        blen = 0
        if isinstance(req_body, str):
            blen = len(req_body)
        elif isinstance(req_body, bytes):
            blen = len(req_body)
        c["body_lengths"].append(float(blen))
        f["_body_len"] = float(blen)

        # json key count
        jk = None
        if isinstance(req_body, (str, bytes)) and req_body:
            try:
                txt = req_body if isinstance(req_body, str) else req_body.decode("utf-8", errors="ignore")
                data = json.loads(txt)
                if isinstance(data, dict):
                    jk = len(data)
                elif isinstance(data, list):
                    jk = len(data)
                else:
                    jk = 1
            except Exception:
                jk = None
        if jk is not None:
            c["json_key_counts"].append(float(jk))
        f["_json_key_count"] = jk

        # duration (future-ready)
        dur = None
        try:
            dur = f.get("duration")
            if dur is not None:
                dur = float(dur)
                c["durations"].append(dur)
        except Exception:
            dur = None
        f["_duration"] = dur
        f["_endpoint"] = key

    # Global fallback stats for size (when cluster too small)
    all_sizes = [float(v) for c in clusters.values() for v in c["sizes"]]
    global_size_stats = _anomaly_quartiles(all_sizes, sensitivity) if all_sizes else {"q1": 0, "q3": 0, "median": 0, "iqr": 0, "lower": 0, "upper": 0}
    # also mean/std for z>3 fallback
    if all_sizes:
        g_mean = sum(all_sizes) / len(all_sizes)
        g_var = sum((x - g_mean) ** 2 for x in all_sizes) / len(all_sizes) if len(all_sizes) > 1 else 0
        g_std = math.sqrt(g_var) if g_var > 0 else 1.0
    else:
        g_mean, g_std = 0, 1.0

    clusters_output: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []

    for key, c in clusters.items():
        sizes = c["sizes"]
        stats = _anomaly_quartiles(sizes, sensitivity) if sizes else {"q1": 0, "q3": 0, "median": 0, "iqr": 0, "lower": 0, "upper": 0}
        # content_type mode
        ct_counter = Counter(c["content_types"])
        mode_ct, mode_ct_cnt = ct_counter.most_common(1)[0] if ct_counter else ("unknown", 0)
        mode_ct_freq = mode_ct_cnt / len(c["content_types"]) if c["content_types"] else 0
        # status mode
        status_counter = Counter(c["statuses"])
        mode_status, mode_status_cnt = status_counter.most_common(1)[0] if status_counter else (None, 0)
        mode_status_freq = mode_status_cnt / len(c["statuses"]) if c["statuses"] else 0

        # timestamp gaps p95
        timestamps_sorted = sorted(c["timestamps"]) if c["timestamps"] else []
        gaps = [timestamps_sorted[i + 1] - timestamps_sorted[i] for i in range(len(timestamps_sorted) - 1)] if len(timestamps_sorted) > 1 else []
        p95_gap = _p95_value(gaps) if gaps else None
        # map timestamp to sorted order for gap lookup
        # Build flow order by timestamp
        flows_by_ts = sorted(c["flows"], key=lambda x: x.get("_timestamp") if x.get("_timestamp") is not None else 0)

        # body lengths stats
        body_stats = _anomaly_quartiles([v for v in c["body_lengths"] if v is not None], sensitivity) if c["body_lengths"] else None
        # json key counts stats
        json_stats = _anomaly_quartiles(c["json_key_counts"], sensitivity) if c["json_key_counts"] else None
        # duration stats (tolerate missing)
        duration_stats = None
        try:
            if c["durations"]:
                duration_stats = _anomaly_quartiles(c["durations"], sensitivity)
        except Exception:
            duration_stats = None

        # cluster output
        clusters_output.append(
            {
                "endpoint": key,
                "count": c["count"],
                "median_size": stats["median"],
                "q1": stats["q1"],
                "q3": stats["q3"],
                "mode_status": mode_status,
                "sample_flow_ids": c["sample_flow_ids"][:3],
                # extra for debugging, not required but useful
                "method": c["method"],
                "path_pattern": c["path_pattern"],
            }
        )

        use_global = c["count"] < min_cluster

        # For each flow evaluate signals
        for idx, f in enumerate(c["flows"]):
            signals: List[str] = []
            scores: Dict[str, float] = {}
            explanations: List[str] = []
            size_val = f["_size"]

            # size outlier (per-cluster IQR or global fallback)
            if not use_global:
                if stats["iqr"] == 0:
                    # If IQR 0, any deviation from median is outlier (common for uniform sizes)
                    if size_val != stats["median"]:
                        signals.append("size_outlier")
                        # distance as absolute diff normalized
                        denom = abs(stats["median"]) if stats["median"] != 0 else 1
                        dist = abs(size_val - stats["median"]) / denom if denom else abs(size_val - stats["median"])
                        scores["iqr"] = round(float(dist), 2)
                        explanations.append(f"size {size_val:.0f} deviates from uniform median {stats['median']:.0f} (IQR 0)")
                else:
                    if size_val < stats["lower"] or size_val > stats["upper"]:
                        signals.append("size_outlier")
                        if size_val > stats["upper"]:
                            dist = (size_val - stats["upper"]) / stats["iqr"] if stats["iqr"] else 0
                        else:
                            dist = (stats["lower"] - size_val) / stats["iqr"] if stats["iqr"] else 0
                        scores["iqr"] = round(float(dist), 2)
                        explanations.append(f"size {size_val:.0f} outside IQR bounds [{stats['lower']:.1f}, {stats['upper']:.1f}] (sensitivity {sensitivity})")
            else:
                # Global fallback z>3
                z = (size_val - g_mean) / g_std if g_std else 0
                scores["z"] = round(float(z), 2)
                if abs(z) > 3:
                    signals.append("size_outlier")
                    # Use global IQR bounds as well if available
                    if size_val < global_size_stats["lower"] or size_val > global_size_stats["upper"]:
                        scores["iqr"] = round(float(abs(z)), 2) if "iqr" not in scores else scores["iqr"]
                    explanations.append(f"size {size_val:.0f} global z={z:.2f} (>3) (small cluster fallback)")
                # Ensure iqr score present for small clusters even if not size outlier? will be set later

            # status_code rarity (mode freq >0.8)
            if mode_status is not None and mode_status_freq > 0.8 and f["_status"] != mode_status and f["_status"] is not None:
                signals.append("status_code_rare")
                rarity = 1 - (status_counter[f["_status"]] / len(c["statuses"])) if len(c["statuses"]) else 1
                scores["status_rarity"] = round(float(rarity), 2)
                explanations.append(f"status {f['_status']} rare vs mode {mode_status} ({mode_status_freq:.0%} mode freq)")

            # content_type shift
            if mode_ct_freq > 0.8 and f["_content_type"] != mode_ct:
                signals.append("content_type_shift")
                explanations.append(f"content_type {f['_content_type']} vs mode {mode_ct}")

            # timestamp inter-arrival gap >p95 (flag flow that follows a large gap)
            if p95_gap is not None and gaps:
                # Find this flow's index in sorted order
                try:
                    sorted_idx = flows_by_ts.index(f)
                except ValueError:
                    sorted_idx = -1
                if sorted_idx > 0:
                    prev_ts = flows_by_ts[sorted_idx - 1].get("_timestamp")
                    cur_ts = f.get("_timestamp")
                    if prev_ts is not None and cur_ts is not None:
                        gap = cur_ts - prev_ts
                        if gap > p95_gap:
                            signals.append("timestamp_gap")
                            explanations.append(f"inter-arrival gap {gap:.2f}s > p95 {p95_gap:.2f}s")

            # request_body length outlier (per-cluster IQR)
            if not lightweight_mode and body_stats and f["_body_len"] is not None:
                bl = f["_body_len"]
                # Only flag if body lengths have variance and cluster large enough
                if not use_global:
                    if body_stats["iqr"] == 0:
                        if bl != body_stats["median"] and bl != 0:
                            # Avoid flagging many zeros if median 0
                            if body_stats["median"] != 0:
                                signals.append("request_body_length_outlier")
                                explanations.append(f"request body length {bl:.0f} deviates from median {body_stats['median']:.0f}")
                    else:
                        if bl < body_stats["lower"] or bl > body_stats["upper"]:
                            signals.append("request_body_length_outlier")
                            explanations.append(f"request body length {bl:.0f} outside IQR [{body_stats['lower']:.1f}, {body_stats['upper']:.1f}]")

            # JSON key-count outlier
            if not lightweight_mode and json_stats and f["_json_key_count"] is not None:
                jk = float(f["_json_key_count"])
                if json_stats["iqr"] == 0:
                    if jk != json_stats["median"]:
                        signals.append("json_key_count_outlier")
                        explanations.append(f"json key count {jk:.0f} deviates from median {json_stats['median']:.0f}")
                else:
                    if jk < json_stats["lower"] or jk > json_stats["upper"]:
                        signals.append("json_key_count_outlier")
                        explanations.append(f"json key count {jk:.0f} outside IQR [{json_stats['lower']:.1f}, {json_stats['upper']:.1f}]")

            # duration outlier (future-ready, tolerant)
            if duration_stats and f.get("_duration") is not None:
                dur = f["_duration"]
                try:
                    if dur < duration_stats["lower"] or dur > duration_stats["upper"]:
                        signals.append("duration_outlier")
                        explanations.append(f"duration {dur:.2f}ms outlier")
                except Exception:
                    pass

            if signals:
                # Composite scoring for sorting
                # Base on number of signals and iqr distance and z
                # Compute z for size for scoring (per-cluster)
                try:
                    if not use_global:
                        if sizes:
                            m = sum(sizes) / len(sizes)
                            var = sum((x - m) ** 2 for x in sizes) / len(sizes) if len(sizes) > 1 else 0
                            std = math.sqrt(var) if var > 0 else 1.0
                            z_val = (size_val - m) / std if std else 0
                        else:
                            z_val = 0
                    else:
                        z_val = (size_val - g_mean) / g_std if g_std else 0
                except Exception:
                    z_val = 0
                if "z" not in scores:
                    scores["z"] = round(float(z_val), 2)
                if "iqr" not in scores:
                    # If not size outlier, iqr 0
                    scores["iqr"] = scores.get("iqr", 0)
                if "status_rarity" not in scores:
                    scores["status_rarity"] = scores.get("status_rarity", 0)

                composite = len(signals) * 10
                composite += abs(scores.get("iqr", 0)) * 3
                composite += abs(scores.get("z", 0)) * 2
                composite += scores.get("status_rarity", 0) * 5
                # Boost for multiple signals
                if "size_outlier" in signals and "status_code_rare" in signals:
                    composite += 5

                anomalies.append(
                    {
                        "flow_id": f["id"],
                        "endpoint": key,
                        "signals": signals,
                        "scores": {"iqr": scores.get("iqr", 0), "z": scores.get("z", 0), "status_rarity": scores.get("status_rarity", 0)},
                        "explanation": "; ".join(explanations),
                        "_composite": composite,
                    }
                )

    # Second-pass for lightweight optimization: fetch bodies for flagged anomalies to check body signals
    if lightweight_mode and anomalies:
        # We flagged based on lightweight signals; now fetch full bodies for those anomalies to evaluate body-length/json outliers
        try:
            anomaly_ids = [a["flow_id"] for a in anomalies]
            # Fetch full rows for anomaly ids (including bodies)
            full_anomaly_flows = controller.recorder.db.get_by_ids(anomaly_ids)
            # Map full data by id
            full_map = {f["id"]: f for f in full_anomaly_flows}
            # For each anomaly, check if body signals would add new signals if we had full data
            # Instead of recomputing cluster stats fully, we can just attempt to augment signals
            for a in anomalies:
                fid = a["flow_id"]
                full = full_map.get(fid)
                if not full:
                    continue
                # full contains request body
                req_body_full = full.get("request", {}).get("body")
                if req_body_full is None:
                    continue
                # Recalculate body length outlier using cluster body stats from lightweight (which were 0) is not accurate
                # For now, just check json key count against simple threshold if body large
                # To keep lightweight path simple, we won't augment heavily; the main body outlier detection is less critical for large DB accuracy vs memory tradeoff
                # We could attempt to add json_key_count anomaly if present
                try:
                    txt = req_body_full if isinstance(req_body_full, str) else req_body_full.decode("utf-8", errors="ignore") if isinstance(req_body_full, bytes) else ""
                    data = json.loads(txt) if txt else None
                    if isinstance(data, dict):
                        jk = len(data)
                        # If cluster json stats not available (lightweight had no bodies), we can flag if jk is large vs typical? For now skip
                        pass
                except Exception:
                    pass
        except Exception:
            pass

    # Sort anomalies by composite score
    anomalies_sorted = sorted(anomalies, key=lambda x: x.get("_composite", 0), reverse=True)
    for a in anomalies_sorted:
        a.pop("_composite", None)

    # Sort clusters by count desc
    clusters_output_sorted = sorted(clusters_output, key=lambda x: -x["count"])

    return {
        "clusters": clusters_output_sorted,
        "anomalies": anomalies_sorted,
        "total_flows": total_flows,
        "clusters_count": len(clusters_output_sorted),
    }


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
