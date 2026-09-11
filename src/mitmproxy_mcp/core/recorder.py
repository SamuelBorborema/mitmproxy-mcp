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


def _env_int(name: str, default: int = 0) -> int:
    """Parse an int env var. Returns default on missing/invalid. 0 = unlimited."""
    try:
        raw = os.environ.get(name)
        if raw is None or str(raw).strip() == "":
            return default
        val = int(str(raw).strip())
        return val if val >= 0 else default
    except Exception:
        return default


def _decode_ws_text(content: bytes) -> Optional[str]:
    """Best-effort decode of WS frame bytes for search/display."""
    if content is None:
        return None
    try:
        return content.decode("utf-8")
    except Exception:
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return None


# Allow-listed direction filters for get_websocket_messages (case-insensitive).
_WS_CLIENT_DIRECTIONS = frozenset({"client", "send", "c2s", "client->server"})
_WS_SERVER_DIRECTIONS = frozenset({"server", "receive", "recv", "s2c", "server->client"})


def _normalize_ws_direction(direction: Optional[str]) -> Optional[str]:
    """Normalize a direction filter to 'client', 'server', or None (both).

    Raises ValueError on unknown values so typos can't silently return
    unfiltered data.
    """
    if direction is None:
        return None
    key = str(direction).strip().lower()
    if key in ("", "both", "all"):
        return None
    if key in _WS_CLIENT_DIRECTIONS:
        return "client"
    if key in _WS_SERVER_DIRECTIONS:
        return "server"
    raise ValueError(
        f"Invalid direction '{direction}'. Use 'client', 'server', or omit for both."
    )


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

    def __init__(
        self,
        db_path: str = "mitm_mcp_traffic.db",
        ws_max_messages_per_flow: Optional[int] = None,
        ws_max_message_bytes: Optional[int] = None,
    ):
        self.db_path = db_path
        # Safety valve: 0 = unlimited (default, "store everything").
        # Overridable via env MITM_WS_MAX_MESSAGES_PER_FLOW /
        # MITM_WS_MAX_MESSAGE_BYTES or explicit constructor args / CLI flags.
        self.ws_max_messages_per_flow = (
            ws_max_messages_per_flow
            if ws_max_messages_per_flow is not None
            else _env_int("MITM_WS_MAX_MESSAGES_PER_FLOW", 0)
        )
        self.ws_max_message_bytes = (
            ws_max_message_bytes
            if ws_max_message_bytes is not None
            else _env_int("MITM_WS_MAX_MESSAGE_BYTES", 0)
        )
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
                ("is_websocket", "ALTER TABLE flows ADD COLUMN is_websocket INTEGER DEFAULT 0"),
                ("ws_message_count", "ALTER TABLE flows ADD COLUMN ws_message_count INTEGER DEFAULT 0"),
                ("ws_stored_count", "ALTER TABLE flows ADD COLUMN ws_stored_count INTEGER DEFAULT 0"),
                ("ws_dropped_count", "ALTER TABLE flows ADD COLUMN ws_dropped_count INTEGER DEFAULT 0"),
                ("ws_closed_by_client", "ALTER TABLE flows ADD COLUMN ws_closed_by_client INTEGER"),
                ("ws_close_code", "ALTER TABLE flows ADD COLUMN ws_close_code INTEGER"),
                ("ws_close_reason", "ALTER TABLE flows ADD COLUMN ws_close_reason TEXT"),
                ("ws_timestamp_end", "ALTER TABLE flows ADD COLUMN ws_timestamp_end REAL"),
                ("ws_truncated_any", "ALTER TABLE flows ADD COLUMN ws_truncated_any INTEGER DEFAULT 0"),
            ]
            for col, stmt in alter_stmts:
                if col not in existing_cols:
                    try:
                        conn.execute(stmt)
                    except sqlite3.OperationalError as e:
                        if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                            continue
                        raise
            conn.execute("""
                CREATE TABLE IF NOT EXISTS websocket_messages (
                    flow_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    from_client INTEGER NOT NULL,
                    opcode INTEGER NOT NULL,
                    is_text INTEGER NOT NULL,
                    content_b64 TEXT,
                    content_text TEXT,
                    timestamp REAL,
                    is_truncated INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    content_hash TEXT,
                    PRIMARY KEY (flow_id, seq)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON flows(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_method ON flows(method)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON flows(status_code)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_size ON flows(size)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ws_flow ON websocket_messages(flow_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_is_websocket ON flows(is_websocket)")

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

        ws_meta = self._extract_ws_meta(flow)

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    id, url, method, status_code,
                    request_headers, request_body,
                    response_headers, response_body,
                    timestamp, size,
                    duration, request_raw, response_raw,
                    request_hash, response_hash,
                    is_websocket, ws_message_count, ws_stored_count,
                    ws_dropped_count, ws_closed_by_client, ws_close_code,
                    ws_close_reason, ws_timestamp_end, ws_truncated_any
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    response_hash=excluded.response_hash,
                    is_websocket=excluded.is_websocket,
                    ws_message_count=excluded.ws_message_count,
                    ws_stored_count=excluded.ws_stored_count,
                    ws_dropped_count=excluded.ws_dropped_count,
                    ws_closed_by_client=excluded.ws_closed_by_client,
                    ws_close_code=excluded.ws_close_code,
                    ws_close_reason=excluded.ws_close_reason,
                    ws_timestamp_end=excluded.ws_timestamp_end,
                    ws_truncated_any=excluded.ws_truncated_any
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
                    ws_meta["is_websocket"],
                    ws_meta["ws_message_count"],
                    ws_meta["ws_stored_count"],
                    ws_meta["ws_dropped_count"],
                    ws_meta["ws_closed_by_client"],
                    ws_meta["ws_close_code"],
                    ws_meta["ws_close_reason"],
                    ws_meta["ws_timestamp_end"],
                    ws_meta["ws_truncated_any"],
                ),
            )

        # Persist frame bodies (outside the flows upsert transaction so a
        # huge burst of frames can't roll back the handshake row).
        try:
            self._sync_websocket_messages(flow)
        except Exception as e:
            print(f"Failed to save websocket messages for {flow.id}: {e}", file=sys.stderr)

    @staticmethod
    def _get_ws_messages(flow) -> List[Any]:
        """Return flow.websocket.messages or [] without raising."""
        try:
            ws = getattr(flow, "websocket", None)
            if ws is None:
                return []
            msgs = getattr(ws, "messages", None)
            return list(msgs) if msgs else []
        except Exception:
            return []

    def _extract_ws_meta(self, flow: http.HTTPFlow) -> Dict[str, Any]:
        """Compute WS columns for the flows row (observed totals + cap accounting)."""
        try:
            ws = getattr(flow, "websocket", None)
        except Exception:
            ws = None
        if ws is None:
            return {
                "is_websocket": 0,
                "ws_message_count": 0,
                "ws_stored_count": 0,
                "ws_dropped_count": 0,
                "ws_closed_by_client": None,
                "ws_close_code": None,
                "ws_close_reason": None,
                "ws_timestamp_end": None,
                "ws_truncated_any": 0,
            }
        try:
            messages = list(getattr(ws, "messages", []) or [])
        except Exception:
            messages = []
        total = len(messages)
        max_msgs = self.ws_max_messages_per_flow or 0
        if max_msgs > 0 and total > max_msgs:
            stored = max_msgs
            dropped = total - max_msgs
        else:
            stored = total
            dropped = 0
        # Truncation flag: true if any stored frame would exceed per-message cap.
        truncated_any = 0
        max_bytes = self.ws_max_message_bytes or 0
        if max_bytes > 0:
            try:
                for m in messages[: stored if stored else 0]:
                    c = getattr(m, "content", b"") or b""
                    if len(c) > max_bytes:
                        truncated_any = 1
                        break
            except Exception:
                pass
        closed_by_client = getattr(ws, "closed_by_client", None)
        if closed_by_client is True:
            closed_int: Optional[int] = 1
        elif closed_by_client is False:
            closed_int = 0
        else:
            closed_int = None
        return {
            "is_websocket": 1,
            "ws_message_count": total,
            "ws_stored_count": stored,
            "ws_dropped_count": dropped,
            "ws_closed_by_client": closed_int,
            "ws_close_code": getattr(ws, "close_code", None),
            "ws_close_reason": getattr(ws, "close_reason", None),
            "ws_timestamp_end": getattr(ws, "timestamp_end", None),
            "ws_truncated_any": truncated_any,
        }

    def _sync_websocket_messages(self, flow: http.HTTPFlow) -> int:
        """Insert missing WS frames for a flow. Returns number newly stored.

        Delta strategy: seqs are contiguous (0..n-1) on the live flow object,
        so frames at seq <= MAX(seq) already stored are skipped without
        re-encoding. Makes the per-frame hook O(1) amortized instead of O(n²).
        """
        messages = self._get_ws_messages(flow)
        if not messages:
            return 0
        max_msgs = self.ws_max_messages_per_flow or 0
        newly = 0
        with self._get_conn() as conn:
            try:
                cur = conn.execute(
                    "SELECT MAX(seq) FROM websocket_messages WHERE flow_id=?",
                    (flow.id,),
                )
                max_row = cur.fetchone()
                start_seq = (int(max_row[0]) + 1) if max_row and max_row[0] is not None else 0
            except Exception:
                start_seq = 0
            for seq, msg in enumerate(messages):
                if seq < start_seq:
                    continue
                # Safety valve 1: per-flow message cap (drop newest beyond cap).
                if max_msgs > 0 and seq >= max_msgs:
                    continue
                try:
                    from_client = 1 if getattr(msg, "from_client", False) else 0
                    # Opcode: 1=TEXT, 2=BINARY (wsproto). Fall back to is_text.
                    try:
                        opcode = int(getattr(getattr(msg, "type", None), "value", 1))
                    except Exception:
                        opcode = 1 if getattr(msg, "is_text", True) else 2
                    is_text = 1 if getattr(msg, "is_text", opcode == 1) else 0
                    content: bytes = getattr(msg, "content", b"") or b""
                    if not isinstance(content, (bytes, bytearray)):
                        content = str(content).encode("utf-8", "replace")
                    else:
                        content = bytes(content)
                    total_bytes = len(content)
                    content_hash = hashlib.sha256(content).hexdigest()
                    try:
                        ts = float(getattr(msg, "timestamp", 0.0) or 0.0)
                    except Exception:
                        ts = 0.0
                    # Safety valve 2: per-message byte cap (truncate, keep hash).
                    is_truncated = 0
                    stored_content = content
                    max_bytes = self.ws_max_message_bytes or 0
                    if max_bytes > 0 and len(content) > max_bytes:
                        stored_content = content[:max_bytes]
                        is_truncated = 1
                    content_b64 = base64.b64encode(stored_content).decode() if stored_content else ""
                    content_text = _decode_ws_text(stored_content)
                    cur = conn.execute(
                        """
                        INSERT OR IGNORE INTO websocket_messages (
                            flow_id, seq, from_client, opcode, is_text,
                            content_b64, content_text, timestamp,
                            is_truncated, total_bytes, content_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            flow.id, seq, from_client, opcode, is_text,
                            content_b64, content_text, ts,
                            is_truncated, total_bytes, content_hash,
                        ),
                    )
                    # rowcount==1 on insert, 0 when OR IGNORE skips a dupe.
                    try:
                        if cur.rowcount == 1:
                            newly += 1
                    except Exception:
                        newly += 1
                except Exception as e:
                    print(f"Skipped WS message {seq} for {flow.id}: {e}", file=sys.stderr)
                    continue
            # Refresh stored/dropped/truncated counters from ground truth.
            try:
                total = len(messages)
                cur = conn.execute(
                    "SELECT COUNT(*), MAX(is_truncated) FROM websocket_messages WHERE flow_id=?",
                    (flow.id,),
                )
                row = cur.fetchone()
                stored = int(row[0]) if row and row[0] is not None else 0
                trunc_any = int(row[1]) if row and len(row) > 1 and row[1] is not None else 0
                dropped = max(0, total - stored) if (self.ws_max_messages_per_flow or 0) > 0 else 0
                conn.execute(
                    """UPDATE flows SET ws_message_count=?, ws_stored_count=?,
                       ws_dropped_count=?, ws_truncated_any=? WHERE id=?""",
                    (total, stored, dropped, trunc_any, flow.id),
                )
            except Exception:
                pass
        return newly

    def get_websocket_messages(
        self,
        flow_id: str,
        limit: int = 100,
        offset: int = 0,
        direction: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Paginated fetch of stored WS frames plus cap accounting.

        Raises ValueError on unknown direction filter values.
        """
        try:
            direction = _normalize_ws_direction(direction)
        except ValueError:
            raise
        if limit < 0:
            limit = 0
        if offset < 0:
            offset = 0
        if limit > 1000:
            limit = 1000
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            try:
                fcur = conn.execute(
                    """SELECT id, url, is_websocket, ws_message_count, ws_stored_count,
                       ws_dropped_count, ws_closed_by_client, ws_close_code,
                       ws_close_reason, ws_timestamp_end, ws_truncated_any
                       FROM flows WHERE id=?""",
                    (flow_id,),
                )
            except sqlite3.OperationalError:
                # Old DB without WS columns
                fcur = conn.execute("SELECT id, url FROM flows WHERE id=?", (flow_id,))
            frow = fcur.fetchone()
            if not frow:
                return None
            keys = set(frow.keys())
            is_ws = int(frow["is_websocket"]) if "is_websocket" in keys and frow["is_websocket"] is not None else 0
            # Fall back to message-table existence for old rows / old DBs.
            mcount_cur = conn.execute(
                "SELECT COUNT(*) FROM websocket_messages WHERE flow_id=?", (flow_id,)
            )
            stored_total = int(mcount_cur.fetchone()[0])
            if not is_ws and stored_total == 0:
                return {
                    "flow_id": flow_id,
                    "url": frow["url"] if "url" in keys else "",
                    "is_websocket": False,
                    "total_observed": 0,
                    "stored": 0,
                    "dropped_count": 0,
                    "truncated_any": False,
                    "messages": [],
                }
            where = "WHERE flow_id=?"
            params: List[Any] = [flow_id]
            if direction == "client":
                where += " AND from_client=1"
            elif direction == "server":
                where += " AND from_client=0"
            try:
                tcur = conn.execute(f"SELECT COUNT(*) FROM websocket_messages {where}", params)
                filtered_total = int(tcur.fetchone()[0])
            except Exception:
                filtered_total = stored_total
            cur = conn.execute(
                f"""SELECT seq, from_client, opcode, is_text, content_b64, content_text,
                    timestamp, is_truncated, total_bytes, content_hash
                    FROM websocket_messages {where} ORDER BY seq ASC LIMIT ? OFFSET ?""",
                (*params, limit, offset),
            )
            msgs = []
            for r in cur.fetchall():
                fc = int(r["from_client"])
                msgs.append(
                    {
                        "seq": int(r["seq"]),
                        "direction": "client->server" if fc == 1 else "server->client",
                        "from_client": bool(fc),
                        "opcode": int(r["opcode"]),
                        "type": "text" if int(r["is_text"]) == 1 else "binary",
                        "is_text": bool(int(r["is_text"])),
                        "timestamp": r["timestamp"],
                        "is_truncated": bool(int(r["is_truncated"] or 0)),
                        "total_bytes": int(r["total_bytes"] or 0),
                        "content_hash": r["content_hash"],
                        "text": r["content_text"],
                        "content_b64": r["content_b64"],
                    }
                )
            def _col(name: str, default: Any = None) -> Any:
                return frow[name] if name in keys else default

            observed = _col("ws_message_count", stored_total)
            try:
                observed = int(observed) if observed is not None else stored_total
            except Exception:
                observed = stored_total
            dropped = _col("ws_dropped_count", max(0, observed - stored_total))
            try:
                dropped = int(dropped) if dropped is not None else 0
            except Exception:
                dropped = 0
            cbc = _col("ws_closed_by_client", None)
            return {
                "flow_id": flow_id,
                "url": _col("url", ""),
                "is_websocket": True,
                "total_observed": observed,
                "stored": stored_total,
                "filtered_total": filtered_total,
                "dropped_count": dropped,
                "truncated_any": bool(_col("ws_truncated_any", 0) or 0),
                "closed_by_client": (bool(cbc) if cbc is not None else None),
                "close_code": _col("ws_close_code", None),
                "close_reason": _col("ws_close_reason", None),
                "timestamp_end": _col("ws_timestamp_end", None),
                "limits": {
                    "max_messages_per_flow": self.ws_max_messages_per_flow or 0,
                    "max_message_bytes": self.ws_max_message_bytes or 0,
                },
                "offset": offset,
                "limit": limit,
                "truncated": (offset + limit) < filtered_total,
                "next_offset": (offset + limit) if (offset + limit) < filtered_total else None,
                "messages": msgs,
            }

    def get_websocket_summary(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Lightweight WS header for inspect_flow without frame bodies."""
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            try:
                cur = conn.execute(
                    """SELECT is_websocket, ws_message_count, ws_stored_count,
                       ws_dropped_count, ws_closed_by_client, ws_close_code,
                       ws_close_reason, ws_timestamp_end, ws_truncated_any
                       FROM flows WHERE id=?""",
                    (flow_id,),
                )
                row = cur.fetchone()
            except sqlite3.OperationalError:
                # Old DB: infer from messages table
                try:
                    cur = conn.execute(
                        "SELECT COUNT(*) AS c FROM websocket_messages WHERE flow_id=?",
                        (flow_id,),
                    )
                    c = int(cur.fetchone()["c"])
                except Exception:
                    return None
                if c == 0:
                    return None
                return {
                    "is_websocket": True,
                    "message_count": c,
                    "stored_count": c,
                    "dropped_count": 0,
                    "truncated_any": False,
                    "closed_by_client": None,
                    "close_code": None,
                    "close_reason": None,
                    "timestamp_end": None,
                }
            if not row:
                return None
            if not row["is_websocket"]:
                # Still check messages table (e.g. row written before migration).
                # Report the counted values, not the (zero) row columns.
                try:
                    cur2 = conn.execute(
                        "SELECT COUNT(*), MAX(is_truncated) FROM websocket_messages WHERE flow_id=?",
                        (flow_id,),
                    )
                    cnt_row = cur2.fetchone()
                    cnt = int(cnt_row[0]) if cnt_row and cnt_row[0] is not None else 0
                    trunc = int(cnt_row[1]) if cnt_row and len(cnt_row) > 1 and cnt_row[1] else 0
                    if cnt == 0:
                        return None
                except Exception:
                    return None
                return {
                    "is_websocket": True,
                    "message_count": cnt,
                    "stored_count": cnt,
                    "dropped_count": 0,
                    "truncated_any": bool(trunc),
                    "closed_by_client": None,
                    "close_code": None,
                    "close_reason": None,
                    "timestamp_end": None,
                }
            cbc = row["ws_closed_by_client"]
            return {
                "is_websocket": True,
                "message_count": int(row["ws_message_count"] or 0),
                "stored_count": int(row["ws_stored_count"] or 0),
                "dropped_count": int(row["ws_dropped_count"] or 0),
                "truncated_any": bool(row["ws_truncated_any"] or 0),
                "closed_by_client": (bool(cbc) if cbc is not None else None),
                "close_code": row["ws_close_code"],
                "close_reason": row["ws_close_reason"],
                "timestamp_end": row["ws_timestamp_end"],
            }

    def get_summary(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            # Tolerate old DBs without WS columns.
            try:
                cur_cols = conn.execute("PRAGMA table_info(flows)")
                flow_cols = {r[1] for r in cur_cols.fetchall()}
            except Exception:
                flow_cols = set()
            ws_select = ""
            if {"is_websocket", "ws_message_count", "ws_stored_count", "ws_dropped_count"}.issubset(flow_cols):
                ws_select = ", is_websocket, ws_message_count, ws_stored_count, ws_dropped_count"
            cursor = conn.execute(
                f"""
                SELECT id, url, method, status_code,
                       response_headers, timestamp, size{ws_select}
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

                entry: Dict[str, Any] = {
                    "id": row["id"],
                    "url": row["url"],
                    "method": row["method"],
                    "status_code": row["status_code"],
                    "content_type": content_type,
                    "size": row["size"],
                    "timestamp": row["timestamp"],
                }
                keys = set(row.keys())
                if "is_websocket" in keys:
                    is_ws = bool(row["is_websocket"] or 0)
                    entry["is_websocket"] = is_ws
                    if is_ws:
                        entry["ws_message_count"] = int(row["ws_message_count"] or 0)
                        entry["ws_stored_count"] = int(row["ws_stored_count"] or 0)
                        entry["ws_dropped_count"] = int(row["ws_dropped_count"] or 0)
                result.append(entry)
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

            detail: Dict[str, Any] = {
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
            # Attach WS summary when present (no frame bodies here; use
            # get_websocket_messages for paginated frames).
            try:
                ws_summary = self.get_websocket_summary(row["id"])
                if ws_summary is not None:
                    detail["websocket"] = ws_summary
            except Exception:
                pass
            return detail

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
            sql += (
                " AND (url LIKE ? OR request_body LIKE ? OR response_body LIKE ?"
                " OR id IN (SELECT flow_id FROM websocket_messages WHERE content_text LIKE ?))"
            )
            wildcard = f"%{query}%"
            params.extend([wildcard, wildcard, wildcard, wildcard])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.OperationalError as e:
                # Old DB without websocket_messages table
                if "websocket_messages" in str(e):
                    sql_fb = sql.replace(
                        " OR id IN (SELECT flow_id FROM websocket_messages WHERE content_text LIKE ?)",
                        "",
                    )
                    params_fb = params[:-2] + params[-1:] if len(params) >= 2 else params
                    # params_fb: drop the ws wildcard (4th), keep limit
                    # Rebuild correctly: [domain?, method?, url, req, resp, limit]
                    cursor = conn.execute(sql_fb, params_fb)
                    return [dict(row) for row in cursor.fetchall()]
                raise

    def clear(self):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM websocket_messages")
            conn.execute("DELETE FROM flows")

    def _has_duration_column(self) -> bool:
        """Check if flows table has a duration column (added by parallel branch)."""
        try:
            with self._get_conn() as conn:
                cur = conn.execute("PRAGMA table_info(flows)")
                cols = [r[1] for r in cur.fetchall()]
                return "duration" in cols
        except Exception:
            return False

    def get_cluster_stats(
        self, values: List[float], sensitivity: float = 1.5
    ) -> Dict[str, Any]:
        """Compute per-cluster IQR stats (pure python, no numpy).

        Returns dict with q1, q3, median, iqr, lower, upper.
        Uses sorted quartiles and IQR*sensitivity bounds.
        """
        if not values:
            return {"q1": 0, "q3": 0, "median": 0, "iqr": 0, "lower": 0, "upper": 0}
        s = sorted(values)
        n = len(s)

        def _percentile(p: float) -> float:
            # p in [0,100]
            if n == 1:
                return float(s[0])
            k = (n - 1) * p / 100.0
            f = int(k // 1)
            c = int(k // 1) if k % 1 == 0 else f + 1
            if f == c:
                return float(s[int(k)])
            d0 = k - f
            # guard bounds
            if c >= n:
                c = n - 1
            if f >= n:
                f = n - 1
            return float(s[f]) * (1 - d0) + float(s[c]) * d0

        q1 = _percentile(25)
        q3 = _percentile(75)
        median = _percentile(50)
        iqr = q3 - q1
        lower = q1 - sensitivity * iqr
        upper = q3 + sensitivity * iqr
        return {"q1": q1, "q3": q3, "median": median, "iqr": iqr, "lower": lower, "upper": upper}

    def get_all_for_analysis(
        self, limit: Optional[int] = None, lightweight: bool = False
    ) -> List[Dict[str, Any]]:
        """Fetch flows for analysis.

        Args:
            limit: Max flows to return. None = all flows.
            lightweight: If True, only select columns needed for clustering
                (no bodies). Reduces memory usage for large captures.
                For large DB, use lightweight first then second-pass fetch
                anomalous bodies only.
        """
        has_duration = self._has_duration_column()
        if lightweight:
            cols = "id, url, method, status_code, request_headers, response_headers, timestamp, size"
            if has_duration:
                cols += ", duration"
            # Lightweight omits bodies to save memory; second-pass fetches bodies for anomalies
            # Keep request_body/response_body out for lightweight
        else:
            cols = "*"

        sql = f"SELECT {cols} FROM flows ORDER BY timestamp DESC"
        params: list = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.execute(sql, params)
            except sqlite3.OperationalError as e:
                # Fallback if duration column missing but was selected (race)
                if "duration" in str(e) and lightweight and has_duration:
                    cols = "id, url, method, status_code, request_headers, response_headers, timestamp, size"
                    sql = f"SELECT {cols} FROM flows ORDER BY timestamp DESC"
                    if limit is not None:
                        sql += " LIMIT ?"
                    cursor = conn.execute(sql, params)
                else:
                    raise
            rows = cursor.fetchall()
            results = []
            for row in rows:
                # Safely extract optional columns
                try:
                    size_val = row["size"] if "size" in row.keys() else 0
                except Exception:
                    size_val = 0
                try:
                    ts_val = row["timestamp"] if "timestamp" in row.keys() else None
                except Exception:
                    ts_val = None
                # duration tolerant
                duration_val = None
                try:
                    if has_duration and "duration" in row.keys():
                        duration_val = row["duration"]
                except Exception:
                    duration_val = None
                # request body handling
                req_body = None
                try:
                    if not lightweight and "request_body" in row.keys():
                        req_body = row["request_body"]
                except Exception:
                    req_body = None
                resp_body = None
                try:
                    if not lightweight and "response_body" in row.keys():
                        resp_body = row["response_body"]
                except Exception:
                    resp_body = None
                results.append(
                    {
                        "id": row["id"],
                        "request": {
                            "url": row["url"],
                            "method": row["method"],
                            "headers": _parse_headers(row["request_headers"]),
                            **(
                                {"body": req_body}
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
                                {"body": resp_body}
                                if not lightweight
                                else {}
                            ),
                        }
                        if row["status_code"] is not None
                        else None,
                        "size": size_val if size_val is not None else 0,
                        "timestamp": ts_val,
                        "duration": duration_val,
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
                "duration", "request_raw", "response_raw", "request_hash", "response_hash",
                "is_websocket", "ws_message_count", "ws_stored_count",
                "ws_dropped_count", "ws_closed_by_client", "ws_close_code",
                "ws_close_reason", "ws_timestamp_end", "ws_truncated_any",
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

                # include timestamp / size / duration when present – needed for diff_flows & anomaly detection
                if "timestamp" in row_keys:
                    entry["timestamp"] = row["timestamp"]
                if "size" in row_keys:
                    entry["size"] = row["size"]
                if "duration" in row_keys:
                    entry["duration"] = row["duration"]

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

    def websocket_start(self, flow: http.HTTPFlow):
        """Handshake completed (101). Ensure the flow row exists as WS."""
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                self._notify()
            except Exception as e:
                print(f"Failed to save websocket start: {e}", file=sys.stderr)

    def websocket_message(self, flow: http.HTTPFlow):
        """Persist the latest frame. Hook is blocking; never raise.

        Note: intentionally does NOT append to the live-flow deque — a busy
        WS stream would otherwise evict all other flows from get_live_flow()
        (deque maxlen=500). Start/end hooks still buffer the handshake.
        """
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self._notify()
            except Exception as e:
                print(f"Failed to save websocket message: {e}", file=sys.stderr)

    def websocket_end(self, flow: http.HTTPFlow):
        """Persist close metadata (close_code / closed_by_client / timestamp_end)."""
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                self._notify()
            except Exception as e:
                print(f"Failed to save websocket end: {e}", file=sys.stderr)

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

    def get_websocket_messages(
        self,
        flow_id: str,
        limit: int = 100,
        offset: int = 0,
        direction: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        return self.db.get_websocket_messages(flow_id, limit=limit, offset=offset, direction=direction)

    def get_websocket_summary(self, flow_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_websocket_summary(flow_id)

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
