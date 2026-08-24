import base64
import hashlib
import json
import os
import shlex
import sqlite3
import sys
from collections import deque
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.io import FlowReader

from .scope import ScopeManager
from .utils import get_safe_text


def _parse_headers(raw: str) -> Dict[str, str]:
    """Parse stored headers into a dict for backward compat.

    Headers are stored as either:
    - list of [key, value] pairs (new format, preserves order)
    - dict (legacy format)
    Returns a dict in both cases. Duplicate keys are collapsed (last wins).
    """
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        return {k: v for k, v in parsed}
    return parsed


def _parse_headers_ordered(raw: str) -> List[List[str]]:
    """Parse stored headers into an ordered list of [key, value] pairs.

    Preserves header ordering and duplicate keys. Used by codegen tools
    where header order matters (e.g. HTTP fingerprinting).
    """
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        return parsed
    return [[k, v] for k, v in parsed.items()]


class SimpleRequest:
    def __init__(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body


class SimpleResponse:
    def __init__(
        self,
        status_code: Optional[int],
        headers: Optional[Dict[str, str]],
        body: Optional[str],
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body


class TrafficDB:
    """Implements SQLite persistence for traffic logs."""

    def __init__(self, db_path: str = "mitm_mcp_traffic.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    method TEXT,
                    status_code INTEGER,
                    request_headers TEXT,
                    request_body TEXT,
                    response_headers TEXT,
                    response_body TEXT,
                    timestamp REAL,
                    size INTEGER,
                    duration REAL DEFAULT 0,
                    request_raw TEXT,
                    response_raw TEXT,
                    request_hash TEXT,
                    response_hash TEXT
                )
            """)
            # Handle existing DB: try ALTER, ignore if column already exists
            # Also check PRAGMA table_info as fallback for strict checking
            try:
                cursor = conn.execute("PRAGMA table_info(flows)")
                existing_cols = {row[1] for row in cursor.fetchall()}
            except Exception:
                existing_cols = set()

            alter_stmts = [
                ("duration", "ALTER TABLE flows ADD COLUMN duration REAL DEFAULT 0"),
                ("request_raw", "ALTER TABLE flows ADD COLUMN request_raw TEXT"),
                ("response_raw", "ALTER TABLE flows ADD COLUMN response_raw TEXT"),
                ("request_hash", "ALTER TABLE flows ADD COLUMN request_hash TEXT"),
                ("response_hash", "ALTER TABLE flows ADD COLUMN response_hash TEXT"),
            ]
            for col, stmt in alter_stmts:
                if col not in existing_cols:
                    try:
                        conn.execute(stmt)
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                            continue
                        raise
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON flows(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_method ON flows(method)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON flows(status_code)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_size ON flows(size)")

    def save_flow(self, flow: http.HTTPFlow):
        """Upserts a flow into the database."""
        req_body = get_safe_text(flow.request)
        resp_body = get_safe_text(flow.response) if flow.response else None

        status_code = flow.response.status_code if flow.response else None
        size = len(flow.response.content) if flow.response and flow.response.content else 0

        # duration
        duration = 0
        try:
            if flow.response and flow.response.timestamp_end and flow.request.timestamp_start:
                duration = flow.response.timestamp_end - flow.request.timestamp_start
        except Exception:
            duration = 0

        # raw bytes handling: prefer raw_content, fallback to content
        def _get_raw_bytes(msg):
            if msg is None:
                return None
            raw = getattr(msg, "raw_content", None)
            if raw is not None:
                return raw
            # fallback to content (already decompressed)
            try:
                c = msg.content
                if c is not None:
                    return c
            except Exception:
                pass
            return None

        req_raw_bytes = _get_raw_bytes(flow.request)
        resp_raw_bytes = _get_raw_bytes(flow.response) if flow.response else None

        req_raw_b64 = base64.b64encode(req_raw_bytes).decode() if req_raw_bytes is not None else None
        resp_raw_b64 = base64.b64encode(resp_raw_bytes).decode() if resp_raw_bytes is not None else None

        req_hash = hashlib.sha256(req_raw_bytes).hexdigest() if req_raw_bytes is not None else None
        resp_hash = hashlib.sha256(resp_raw_bytes).hexdigest() if resp_raw_bytes is not None else None

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    id, url, method, status_code,
                    request_headers, request_body,
                    response_headers, response_body,
                    timestamp, size,
                    duration, request_raw, response_raw,
                    request_hash, response_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    url=excluded.url,
                    method=excluded.method,
                    status_code=excluded.status_code,
                    request_headers=excluded.request_headers,
                    request_body=excluded.request_body,
                    response_headers=excluded.response_headers,
                    response_body=excluded.response_body,
                    size=excluded.size,
                    duration=excluded.duration,
                    request_raw=excluded.request_raw,
                    response_raw=excluded.response_raw,
                    request_hash=excluded.request_hash,
                    response_hash=excluded.response_hash
            """,
                (
                    flow.id,
                    flow.request.url,
                    flow.request.method,
                    status_code,
                    json.dumps(
                        [
                            [k.decode("latin-1"), v.decode("latin-1")]
                            for k, v in flow.request.headers.fields
                        ],
                    ),
                    req_body,
                    json.dumps(
                        [
                            [k.decode("latin-1"), v.decode("latin-1")]
                            for k, v in flow.response.headers.fields
                        ],
                    )
                    if flow.response
                    else None,
                    resp_body,
                    flow.request.timestamp_start,
                    size,
                    duration,
                    req_raw_b64,
                    resp_raw_b64,
                    req_hash,
                    resp_hash,
                ),
            )

    def get_summary(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, url, method, status_code,
                       response_headers, timestamp, size
                FROM flows
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """,
                (limit, offset),
            )

            rows = cursor.fetchall()
            result = []
            for row in rows:
                content_type = "unknown"
                if row["response_headers"]:
                    headers = _parse_headers(row["response_headers"])
                    content_type = headers.get(
                        "content-type",
                        headers.get("Content-Type", "unknown"),
                    )

                result.append(
                    {
                        "id": row["id"],
                        "url": row["url"],
                        "method": row["method"],
                        "status_code": row["status_code"],
                        "content_type": content_type,
                        "size": row["size"],
                        "timestamp": row["timestamp"],
                    }
                )
            return result

    def get_detail(self, flow_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
            row = cursor.fetchone()

            if not row:
                return None

            req_headers = _parse_headers(row["request_headers"])
            resp_headers = _parse_headers(row["response_headers"]) if row["response_headers"] else None

            simple_request = SimpleRequest(
                method=row["method"],
                url=row["url"],
                headers=req_headers,
                body=row["request_body"],
            )
            simple_response = (
                SimpleResponse(
                    status_code=row["status_code"],
                    headers=resp_headers,
                    body=row["response_body"],
                )
                if row["status_code"] is not None
                else None
            )

            return {
                "id": row["id"],
                "request": {
                    "method": simple_request.method,
                    "url": simple_request.url,
                    "headers": simple_request.headers,
                    "body_preview": (simple_request.body[:2000] if simple_request.body else None),
                },
                "response": {
                    "status_code": simple_response.status_code,
                    "headers": simple_response.headers,
                    "body_preview": (simple_response.body[:2000] if simple_response.body else None),
                }
                if simple_response
                else None,
                "curl_command": self._generate_curl(simple_request),
            }

    def search(
        self, query: str = None, domain: str = None, method: str = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        sql = "SELECT id, url, method, status_code, timestamp FROM flows WHERE 1=1"
        params = []

        if domain:
            sql += " AND url LIKE ?"
            params.append(f"%{domain}%")

        if method:
            sql += " AND method = ?"
            params.append(method.upper())

        if query:
            sql += " AND (url LIKE ? OR request_body LIKE ? OR response_body LIKE ?)"
            wildcard = f"%{query}%"
            params.extend([wildcard, wildcard, wildcard])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def clear(self):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM flows")

    def get_all_for_analysis(
        self, limit: Optional[int] = None, lightweight: bool = False
    ) -> List[Dict[str, Any]]:
        """Fetch flows for analysis.

        Args:
            limit: Max flows to return. None = all flows.
            lightweight: If True, only select columns needed for clustering
                (no bodies). Reduces memory usage for large captures.
        """
        if lightweight:
            cols = "id, url, method, status_code, request_headers, response_headers"
        else:
            cols = "*"

        sql = f"SELECT {cols} FROM flows ORDER BY timestamp DESC"
        params: list = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    {
                        "id": row["id"],
                        "request": {
                            "url": row["url"],
                            "method": row["method"],
                            "headers": _parse_headers(row["request_headers"]),
                            **(
                                {"body": row["request_body"]}
                                if not lightweight
                                else {}
                            ),
                        },
                        "response": {
                            "status_code": row["status_code"],
                            "headers": _parse_headers(row["response_headers"])
                            if row["response_headers"]
                            else {},
                            **(
                                {"body": row["response_body"]}
                                if not lightweight
                                else {}
                            ),
                        }
                        if row["status_code"]
                        else None,
                    }
                )
            return results

    def get_by_ids(
        self,
        flow_ids: List[str],
        columns: Optional[List[str]] = None,
        ordered_headers: bool = False,
    ) -> List[Dict[str, Any]]:
        """Fetch flows by IDs.

        Args:
            flow_ids: List of flow IDs to fetch.
            columns: SQL columns to select. None = all columns.
                Reduces memory when response bodies aren't needed.
            ordered_headers: If True, return headers as ordered [key, value]
                pairs instead of dict. Used by codegen for header ordering.
        """
        if not flow_ids:
            return []

        if columns:
            allowed_cols = {
                "id", "url", "method", "status_code", "request_headers", 
                "request_body", "response_headers", "response_body", "timestamp", "size",
                "duration", "request_raw", "response_raw", "request_hash", "response_hash"
            }
            invalid_cols = [c for c in columns if c not in allowed_cols]
            if invalid_cols:
                raise ValueError(f"Invalid columns requested: {invalid_cols}")
            cols = ", ".join(columns)
        else:
            cols = "*"

        placeholders = ",".join(["?"] * len(flow_ids))
        header_fn = _parse_headers_ordered if ordered_headers else _parse_headers

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                f"SELECT {cols} FROM flows WHERE id IN ({placeholders})",
                flow_ids,
            )
            rows = cursor.fetchall()
            row_keys = set(rows[0].keys()) if rows else set()
            results = []
            for row in rows:
                entry: Dict[str, Any] = {"id": row["id"]}

                req: Dict[str, Any] = {}
                if "url" in row_keys:
                    req["url"] = row["url"]
                if "method" in row_keys:
                    req["method"] = row["method"]
                if "request_headers" in row_keys and row["request_headers"]:
                    req["headers"] = header_fn(row["request_headers"])
                if "request_body" in row_keys:
                    req["body"] = row["request_body"]
                if req:
                    entry["request"] = req

                if "status_code" in row_keys and row["status_code"] is not None:
                    resp: Dict[str, Any] = {"status_code": row["status_code"]}
                    if "response_headers" in row_keys and row["response_headers"]:
                        resp["headers"] = header_fn(row["response_headers"])
                    if "response_body" in row_keys:
                        resp["body"] = row["response_body"]
                    entry["response"] = resp

                # include timestamp / size when present – needed for diff_flows
                if "timestamp" in row_keys:
                    entry["timestamp"] = row["timestamp"]
                if "size" in row_keys:
                    entry["size"] = row["size"]

                results.append(entry)
            return results

    def get_full_flow(self, flow_id: str, ordered_headers: bool = False) -> Optional[Dict[str, Any]]:
        """Return full flow dict with request+response bodies and metadata.

        Fetches all columns for a single id via get_by_ids pattern and
        normalises header ordering when requested. Returns None if not found.
        """
        results = self.get_by_ids([flow_id], ordered_headers=ordered_headers)
        if not results:
            return None
        return results[0]

    def import_from_file(
        self,
        file_path: str,
        append: bool = False,
        scope: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Import flows from a HAR or mitmproxy flow file.

        Uses mitmproxy's FlowReader which auto-detects format (HAR if JSON,
        native tnetstring otherwise).

        Args:
            file_path: Path to .har or .mitm/.flow file.
            append: If False, clear existing traffic before import.
            scope: Optional list of domains to filter by during import.

        Returns:
            Dict with import stats: {"imported": int, "skipped": int, "errors": int}
        """
        if not append:
            self.clear()

        stats = {"imported": 0, "skipped": 0, "errors": 0}

        if not os.path.exists(file_path):
            print(f"File not found: {file_path}", file=sys.stderr)
            return stats

        allowed_exts = ('.har', '.mitm', '.flow', '.json', '.zhar')
        if not any(str(file_path).lower().endswith(ext) for ext in allowed_exts):
            print(f"Unsupported file extension: {file_path}", file=sys.stderr)
            return stats

        # Handle .zhar (zlib-compressed HAR) and also .har/.json that may be compressed via compress flag
        lower_path = str(file_path).lower()
        use_zlib = lower_path.endswith('.zhar')
        file_obj = None
        raw_bytes = None
        if use_zlib or lower_path.endswith(('.har', '.json')):
            try:
                with open(file_path, "rb") as check_f:
                    raw_bytes = check_f.read()
                if use_zlib:
                    import zlib
                    try:
                        decompressed = zlib.decompress(raw_bytes)
                        stripped = decompressed.lstrip()
                        if stripped.startswith(b"{") or stripped.startswith(b"["):
                            raw_bytes = decompressed
                    except Exception:
                        pass
                else:
                    if raw_bytes[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
                        import zlib
                        try:
                            decompressed = zlib.decompress(raw_bytes)
                            stripped = decompressed.lstrip()
                            if stripped.startswith(b"{") or stripped.startswith(b"["):
                                raw_bytes = decompressed
                        except Exception:
                            pass
                import io
                file_obj = io.BytesIO(raw_bytes)
            except Exception:
                file_obj = None

        def _process_stream(reader):
            for flow in reader.stream():
                try:
                    if not isinstance(flow, http.HTTPFlow):
                        stats["skipped"] += 1
                        continue
                    if scope:
                        host = urlparse(flow.request.url).hostname or ""
                        if not any(host == d or host.endswith("." + d) for d in scope):
                            stats["skipped"] += 1
                            continue
                    self.save_flow(flow)
                    stats["imported"] += 1
                except Exception as e:
                    stats["errors"] += 1
                    print(f"Skipped flow during import: {e}", file=sys.stderr)

        if file_obj is not None:
            reader = FlowReader(file_obj)
            _process_stream(reader)
        else:
            with open(file_path, "rb") as f:
                reader = FlowReader(f)
                _process_stream(reader)

        return stats

    def _generate_curl(self, request: SimpleRequest) -> str:
        try:
            cmd = ["curl", "-X", request.method]
            cmd.append(shlex.quote(request.url))

            for key, value in request.headers.items():
                cmd.append("-H")
                cmd.append(shlex.quote(f"{key}: {value}"))

            if request.body:
                cmd.append("-d")
                cmd.append(shlex.quote(request.body))

            return " ".join(cmd)
        except Exception:
            return "Error generating curl command"

    # Helper to reconstruct a minimal request for replay
    def get_flow_object(self, flow_id: str) -> Optional[SimpleRequest]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT method, url, request_headers, request_body, response_headers, response_body, status_code FROM flows WHERE id = ?",
                (flow_id,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            headers = _parse_headers(row["request_headers"])
            obj = SimpleRequest(
                method=row["method"],
                url=row["url"],
                headers=headers,
                body=row["request_body"],
            )
            # Attach response info for callers that need it (e.g. diff_flows, get_flow_schema)
            # Keep backward compat: .body/.headers/.method remain for request.
            # Response is available as .response if row has it.
            if row["status_code"] is not None:
                resp_headers = _parse_headers(row["response_headers"]) if row["response_headers"] else None
                obj.response = SimpleResponse(  # type: ignore[attr-defined]
                    status_code=row["status_code"],
                    headers=resp_headers,
                    body=row["response_body"],
                )
            else:
                obj.response = None  # type: ignore[attr-defined]
            # Also expose full flow dict for convenience
            obj.request_body = row["request_body"]  # type: ignore[attr-defined]
            obj.response_body = row["response_body"]  # type: ignore[attr-defined]
            return obj


class TrafficRecorder:
    """Captures flows into SQLite for inspection."""

    def __init__(self, scope: ScopeManager):
        self.scope = scope
        self.db = TrafficDB()
        # Keep a small in-memory deque of objects for legacy usage (like replay)
        # Note: This buffer is non-persistent, SQLite is the main storage.
        self.flows = deque(maxlen=500)
        # Optional callback injected by server.py to publish ResourceUpdated
        # events on flow save. Kept as Optional[Callable[[], None]] to avoid
        # circular imports; server wires `recorder.on_flow = _notify_live_flow`.
        self.on_flow: Optional[Callable[[], None]] = None

    def _notify(self) -> None:
        """Invoke the live-flow callback if wired, never raising."""
        if self.on_flow is None:
            return
        try:
            self.on_flow()
        except Exception as e:
            print(f"Failed to notify live flow subscriber: {e}", file=sys.stderr)

    def request(self, flow: http.HTTPFlow):
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                print(
                    f"DEBUG: Request saved for {flow.request.url}",
                    file=sys.stderr,
                )
                self._notify()
            except Exception as e:
                print(f"Failed to save request flow: {e}", file=sys.stderr)

    def response(self, flow: http.HTTPFlow):
        print(
            f"DEBUG: Response hook called for {flow.request.url}",
            file=sys.stderr,
        )
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                print(f"DEBUG: Saved flow {flow.id}", file=sys.stderr)
                self._notify()
            except Exception as e:
                print(f"Failed to save flow: {e}", file=sys.stderr)

    def error(self, flow: http.HTTPFlow):
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                self._notify()
            except Exception as e:
                print(f"Failed to save flow error: {e}", file=sys.stderr)

    def get_flow_summary(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.db.get_summary(limit=limit)

    def get_flow_detail(self, flow_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_detail(flow_id)

    def get_live_flow(self, flow_id: str) -> Optional[http.HTTPFlow]:
        """Return a richer in-memory HTTPFlow when it is still buffered."""
        for flow in reversed(self.flows):
            if flow.id == flow_id:
                return flow
        return None

    def search(self, query: str, domain: str, method: str, limit: int):
        return self.db.search(query, domain, method, limit)

    def clear(self):
        self.db.clear()

    def get_all_for_analysis(
        self, limit: Optional[int] = None, lightweight: bool = False
    ) -> List[Dict[str, Any]]:
        return self.db.get_all_for_analysis(limit, lightweight=lightweight)

    def _enrich_with_live_flow(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback for binary NULL bodies: hydrate from live deque bytes if available."""
        fid = entry.get("id")
        if not fid:
            return entry
        live = self.get_live_flow(fid)
        if not live:
            return entry
        # Request body fallback
        req = entry.get("request")
        if req is not None and req.get("body") is None:
            try:
                # Prefer decoded text if available, else surrogate-escaped bytes
                txt = live.request.get_text(strict=False)
                if txt is not None:
                    req["body"] = txt
                elif live.request.content:
                    # surrogateescape preserves binary bytes as surrogates for diff detection
                    req["body"] = live.request.content.decode("utf-8", errors="surrogateescape")
            except Exception:
                pass
            # Also ensure headers fallback if missing? DB already has headers
        # Response body fallback
        resp = entry.get("response")
        if resp is not None and resp.get("body") is None:
            try:
                if live.response:
                    txt = live.response.get_text(strict=False)
                    if txt is not None:
                        resp["body"] = txt
                    elif live.response.content:
                        resp["body"] = live.response.content.decode("utf-8", errors="surrogateescape")
            except Exception:
                pass
        # If response missing entirely but live has one, synthesize
        if "response" not in entry and live.response:
            try:
                txt = live.response.get_text(strict=False)
                if txt is None and live.response.content:
                    txt = live.response.content.decode("utf-8", errors="surrogateescape")
                entry["response"] = {
                    "status_code": live.response.status_code,
                    "headers": [[k.decode("latin-1"), v.decode("latin-1")] for k, v in live.response.headers.fields]
                    if live.response.headers
                    else [],
                    "body": txt,
                }
            except Exception:
                pass
        return entry

    def get_by_ids(
        self,
        flow_ids: List[str],
        columns: Optional[List[str]] = None,
        ordered_headers: bool = False,
    ) -> List[Dict[str, Any]]:
        results = self.db.get_by_ids(flow_ids, columns=columns, ordered_headers=ordered_headers)
        # Enrich binary NULL bodies from live flow deque when possible
        enriched: List[Dict[str, Any]] = []
        for entry in results:
            enriched.append(self._enrich_with_live_flow(entry))
        return enriched

    def get_full_flow(self, flow_id: str, ordered_headers: bool = False) -> Optional[Dict[str, Any]]:
        """Fetch full flow (request+response+metadata) with live fallback."""
        raw = self.db.get_full_flow(flow_id, ordered_headers=ordered_headers)
        if raw is None:
            return None
        return self._enrich_with_live_flow(raw)
