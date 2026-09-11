import os
import tempfile

import pytest
from mitmproxy import connection, http
from mitmproxy.websocket import WebSocketData, WebSocketMessage
from wsproto.frame_protocol import Opcode

from mitmproxy_mcp.core.recorder import TrafficDB, TrafficRecorder
from mitmproxy_mcp.core.scope import ScopeManager
from mitmproxy_mcp.models import ScopeConfig
from mitmproxy_mcp.core.server import (
    controller,
    get_websocket_messages,
    proxy_status,
)


def _make_ws_flow(url="https://example.com/chat", messages=None):
    client = connection.Client(
        peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0), timestamp_start=1234567890.0
    )
    server = connection.Server(address=("example.com", 443))
    flow = http.HTTPFlow(client, server, live=False)
    flow.request = http.Request.make(
        "GET", url, content=b"",
        headers=[(b"Upgrade", b"websocket"), (b"Sec-WebSocket-Version", b"13")],
    )
    flow.request.timestamp_start = 1234567890.0
    flow.request.timestamp_end = 1234567890.0
    flow.response = http.Response.make(
        101, content=b"", headers=[(b"Upgrade", b"websocket")],
    )
    flow.response.timestamp_start = 1234567890.0
    flow.response.timestamp_end = 1234567890.1
    ws = WebSocketData()
    for m in messages or []:
        ws.messages.append(m)
    flow.websocket = ws
    return flow


def _make_tmp_db(**kwargs):
    tmp = tempfile.mktemp(suffix=".db")
    return TrafficDB(db_path=tmp, **kwargs), tmp


def test_save_and_fetch_text_and_binary():
    db, path = _make_tmp_db()
    try:
        flow = _make_ws_flow(messages=[
            WebSocketMessage(Opcode.TEXT, True, b"hello server"),
            WebSocketMessage(Opcode.TEXT, False, b"hello client"),
            WebSocketMessage(Opcode.BINARY, True, b"\x00\x01\x02"),
        ])
        db.save_flow(flow)
        detail = db.get_detail(flow.id)
        assert detail["websocket"]["is_websocket"] is True
        assert detail["websocket"]["message_count"] == 3
        assert detail["websocket"]["stored_count"] == 3
        assert detail["websocket"]["dropped_count"] == 0

        summary = db.get_summary(limit=5)
        row = next(r for r in summary if r["id"] == flow.id)
        assert row["is_websocket"] is True
        assert row["ws_message_count"] == 3

        msgs = db.get_websocket_messages(flow.id)
        assert msgs["total_observed"] == 3
        assert msgs["stored"] == 3
        assert len(msgs["messages"]) == 3
        assert msgs["messages"][0]["direction"] == "client->server"
        assert msgs["messages"][0]["type"] == "text"
        assert msgs["messages"][0]["text"] == "hello server"
        assert msgs["messages"][1]["direction"] == "server->client"
        assert msgs["messages"][2]["type"] == "binary"
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_direction_filter_and_pagination():
    db, path = _make_tmp_db()
    try:
        flow = _make_ws_flow(messages=[
            WebSocketMessage(Opcode.TEXT, True, b"a"),
            WebSocketMessage(Opcode.TEXT, False, b"b"),
            WebSocketMessage(Opcode.TEXT, True, b"c"),
        ])
        db.save_flow(flow)
        c2s = db.get_websocket_messages(flow.id, direction="client")
        assert len(c2s["messages"]) == 2
        s2c = db.get_websocket_messages(flow.id, direction="server")
        assert len(s2c["messages"]) == 1
        p1 = db.get_websocket_messages(flow.id, limit=2, offset=0)
        assert p1["truncated"] is True
        assert p1["next_offset"] == 2
        p2 = db.get_websocket_messages(flow.id, limit=2, offset=2)
        assert len(p2["messages"]) == 1
        assert p2["truncated"] is False
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_max_messages_cap_counts_dropped():
    db, path = _make_tmp_db(ws_max_messages_per_flow=3)
    try:
        msgs = [WebSocketMessage(Opcode.TEXT, True, f"m{i}".encode()) for i in range(5)]
        flow = _make_ws_flow(messages=msgs)
        db.save_flow(flow)
        out = db.get_websocket_messages(flow.id)
        assert out["total_observed"] == 5
        assert out["stored"] == 3
        assert out["dropped_count"] == 2
        assert len(out["messages"]) == 3
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_max_bytes_truncates_but_keeps_hash():
    db, path = _make_tmp_db(ws_max_message_bytes=5)
    try:
        flow = _make_ws_flow(messages=[WebSocketMessage(Opcode.TEXT, True, b"A" * 10)])
        db.save_flow(flow)
        out = db.get_websocket_messages(flow.id)
        m = out["messages"][0]
        assert m["is_truncated"] is True
        assert m["total_bytes"] == 10
        assert out["truncated_any"] is True
        assert m["content_hash"] is not None
        # stored slice decodes to 5 chars
        import base64
        assert len(base64.b64decode(m["content_b64"])) == 5
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_websocket_end_metadata():
    db, path = _make_tmp_db()
    try:
        flow = _make_ws_flow(messages=[WebSocketMessage(Opcode.TEXT, True, b"hi")])
        flow.websocket.closed_by_client = True
        flow.websocket.close_code = 1000
        flow.websocket.close_reason = "done"
        flow.websocket.timestamp_end = 99.0
        db.save_flow(flow)
        detail = db.get_detail(flow.id)
        ws = detail["websocket"]
        assert ws["closed_by_client"] is True
        assert ws["close_code"] == 1000
        assert ws["close_reason"] == "done"
        assert ws["timestamp_end"] == 99.0
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_search_finds_frame_text():
    db, path = _make_tmp_db()
    try:
        flow = _make_ws_flow(messages=[
            WebSocketMessage(Opcode.TEXT, True, b"unique-ws-token-12345"),
        ])
        db.save_flow(flow)
        hits = db.search(query="unique-ws-token-12345")
        assert any(h["id"] == flow.id for h in hits)
        assert db.search(query="no-such-token-zzz") == [] or all(
            h["id"] != flow.id for h in db.search(query="no-such-token-zzz")
        )
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_recorder_hooks_and_clear_cascade():
    scope = ScopeManager(ScopeConfig())
    rec = TrafficRecorder(scope)
    tmp = tempfile.mktemp(suffix=".db")
    rec.db = TrafficDB(tmp)
    try:
        flow = _make_ws_flow(messages=[WebSocketMessage(Opcode.TEXT, True, b"x")])
        rec.websocket_message(flow)
        assert rec.db.get_websocket_messages(flow.id)["stored"] == 1
        flow.websocket.messages.append(WebSocketMessage(Opcode.TEXT, False, b"y"))
        rec.websocket_end(flow)
        assert rec.db.get_websocket_messages(flow.id)["stored"] == 2
        rec.clear()
        import sqlite3
        with sqlite3.connect(tmp) as conn:
            assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM websocket_messages").fetchone()[0] == 0
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


@pytest.mark.asyncio
async def test_get_websocket_messages_tool():
    old_db = controller.recorder.db
    tmp = tempfile.mktemp(suffix=".db")
    controller.recorder.db = TrafficDB(tmp)
    try:
        controller.recorder.clear()
        flow = _make_ws_flow(messages=[WebSocketMessage(Opcode.TEXT, True, b"ping")])
        controller.recorder.db.save_flow(flow)
        ok = await get_websocket_messages(flow.id)
        assert ok["is_websocket"] is True
        assert len(ok["messages"]) == 1

        # non-WS flow
        c = connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0), timestamp_start=1.0)
        s = connection.Server(address=("example.com", 80))
        plain = http.HTTPFlow(c, s, live=False)
        plain.request = http.Request.make("GET", "https://example.com/api", content=b"")
        plain.request.timestamp_start = 1.0
        plain.response = http.Response.make(200, content=b"hi")
        controller.recorder.db.save_flow(plain)
        err = await get_websocket_messages(plain.id)
        assert "error" in err
        missing = await get_websocket_messages("does-not-exist")
        assert "error" in missing
    finally:
        controller.recorder.db = old_db
        if os.path.exists(tmp):
            os.remove(tmp)


@pytest.mark.asyncio
async def test_proxy_status_ws_keys():
    res = await proxy_status()
    assert "websocket_flow_count" in res
    assert "websocket_message_count" in res
    assert "ws_limits" in res
    assert isinstance(res["websocket_flow_count"], int)


def test_old_db_migration_and_fallbacks():
    import sqlite3

    tmp = tempfile.mktemp(suffix=".db")
    try:
        # Build a legacy DB without any WS columns/table.
        with sqlite3.connect(tmp) as conn:
            conn.execute("""
                CREATE TABLE flows (
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
            conn.execute(
                "INSERT INTO flows (id, url, method, status_code, request_headers, timestamp, size)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("legacy-1", "https://example.com/old", "GET", 200, "[]", 1.0, 0),
            )
        db = TrafficDB(db_path=tmp)
        with sqlite3.connect(tmp) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(flows)").fetchall()}
            assert "is_websocket" in cols
            assert "ws_message_count" in cols
            assert "ws_dropped_count" in cols
            tbls = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            assert "websocket_messages" in tbls
        # Fallback paths must not raise on the migrated legacy row.
        summary = db.get_summary(limit=5)
        assert any(r["id"] == "legacy-1" for r in summary)
        detail = db.get_detail("legacy-1")
        assert detail is not None
        assert "websocket" not in detail
        assert db.search(query="example.com")
        ws = db.get_websocket_messages("legacy-1")
        assert ws["is_websocket"] is False
        assert ws["messages"] == []
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def test_scope_filter_drops_ws_frames():
    rec_allowed = TrafficRecorder(ScopeManager(ScopeConfig(allowed_domains=["allowed.com"])))
    tmp = tempfile.mktemp(suffix=".db")
    rec_allowed.db = TrafficDB(tmp)
    try:
        blocked = _make_ws_flow(
            url="https://blocked.com/chat",
            messages=[WebSocketMessage(Opcode.TEXT, True, b"secret")],
        )
        rec_allowed.websocket_message(blocked)
        assert rec_allowed.db.get_websocket_messages(blocked.id) is None
        assert not any(
            h["id"] == blocked.id for h in rec_allowed.db.search(query="secret")
        )
        allowed = _make_ws_flow(
            url="https://allowed.com/chat",
            messages=[WebSocketMessage(Opcode.TEXT, True, b"welcome")],
        )
        rec_allowed.websocket_message(allowed)
        rec_allowed.websocket_end(allowed)
        out = rec_allowed.db.get_websocket_messages(allowed.id)
        assert out is not None and out["stored"] == 1
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


@pytest.mark.asyncio
async def test_har_roundtrip_preserves_ws():
    from pathlib import Path

    from mitmproxy_mcp.core.server import export_har, load_traffic_file

    old_db = controller.recorder.db
    tmp = tempfile.mktemp(suffix=".db", dir=".")
    controller.recorder.db = TrafficDB(tmp)
    out = "ws_roundtrip_tmp.har"
    try:
        controller.recorder.clear()
        flow = _make_ws_flow(messages=[
            WebSocketMessage(Opcode.TEXT, True, b"hello"),
            WebSocketMessage(Opcode.TEXT, False, b"world"),
        ])
        controller.recorder.db.save_flow(flow)
        res = await export_har(out)
        assert res["status"] == "ok"
        assert res["entries"] == 1
        har = __import__("json").loads(Path(out).read_text())
        entry = har["log"]["entries"][0]
        ws_msgs = entry.get("_webSocketMessages") or []
        assert len(ws_msgs) == 2
        assert {m["type"] for m in ws_msgs} == {"send", "receive"}
        # NOTE: mitmproxy's FlowReader drops _webSocketMessages on HAR import
        # (verified: re-read flow has websocket=None upstream), so re-import
        # only preserves the 101 handshake row, not frames.
        controller.recorder.clear()
        res2 = await load_traffic_file(out)
        assert res2["status"] == "ok"
        assert res2["imported"] == 1
        rows = controller.recorder.db.search(query="example.com/chat")
        assert len(rows) == 1
    finally:
        controller.recorder.db = old_db
        for p in (out, tmp):
            if os.path.exists(p):
                os.remove(p)


def test_ws_env_and_cli_defaults(monkeypatch):
    monkeypatch.setenv("MITM_WS_MAX_MESSAGES_PER_FLOW", "7")
    monkeypatch.setenv("MITM_WS_MAX_MESSAGE_BYTES", "11")
    tmp = tempfile.mktemp(suffix=".db")
    try:
        db = TrafficDB(db_path=tmp)
        assert db.ws_max_messages_per_flow == 7
        assert db.ws_max_message_bytes == 11
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    for bad in ("abc", "-5", ""):
        monkeypatch.setenv("MITM_WS_MAX_MESSAGES_PER_FLOW", bad)
        monkeypatch.setenv("MITM_WS_MAX_MESSAGE_BYTES", bad)
        tmp2 = tempfile.mktemp(suffix=".db")
        try:
            db2 = TrafficDB(db_path=tmp2)
            assert db2.ws_max_messages_per_flow == 0
            assert db2.ws_max_message_bytes == 0
        finally:
            if os.path.exists(tmp2):
                os.remove(tmp2)
    # Explicit ctor args override env.
    monkeypatch.setenv("MITM_WS_MAX_MESSAGES_PER_FLOW", "7")
    tmp3 = tempfile.mktemp(suffix=".db")
    try:
        db3 = TrafficDB(db_path=tmp3, ws_max_messages_per_flow=3)
        assert db3.ws_max_messages_per_flow == 3
    finally:
        if os.path.exists(tmp3):
            os.remove(tmp3)


def test_get_websocket_edge_inputs():
    db, path = _make_tmp_db()
    try:
        flow = _make_ws_flow(messages=[
            WebSocketMessage(Opcode.TEXT, True, b"a"),
            WebSocketMessage(Opcode.TEXT, False, b"b"),
        ])
        db.save_flow(flow)
        over = db.get_websocket_messages(flow.id, limit=5000)
        assert len(over["messages"]) == 2
        assert over["limit"] == 1000
        neg = db.get_websocket_messages(flow.id, limit=-1, offset=-5)
        assert neg["messages"] == []
        unknown_dir = db.get_websocket_messages(flow.id, direction="sideways")
        assert len(unknown_dir["messages"]) == 2
        past = db.get_websocket_messages(flow.id, limit=10, offset=99)
        assert past["messages"] == []
        assert past["truncated"] is False
        # Flow without websocket attr / empty messages never crashes.
        c = connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0), timestamp_start=1.0)
        s = connection.Server(address=("example.com", 80))
        plain = http.HTTPFlow(c, s, live=False)
        plain.request = http.Request.make("GET", "https://example.com/x", content=b"")
        plain.request.timestamp_start = 1.0
        plain.response = http.Response.make(200, content=b"hi")
        db.save_flow(plain)
        assert db.get_websocket_messages(plain.id)["is_websocket"] is False
        empty_ws = _make_ws_flow(messages=[])
        db.save_flow(empty_ws)
        assert db.get_websocket_messages(empty_ws.id)["messages"] == []
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_empty_and_nonutf8_binary_frames():
    import base64

    db, path = _make_tmp_db()
    try:
        raw_bin = b"\xff\xfe\x00\x01binary"
        flow = _make_ws_flow(messages=[
            WebSocketMessage(Opcode.BINARY, True, b""),
            WebSocketMessage(Opcode.BINARY, False, raw_bin),
            WebSocketMessage(Opcode.TEXT, True, b"plain"),
        ])
        db.save_flow(flow)
        out = db.get_websocket_messages(flow.id)
        assert out["stored"] == 3
        by_seq = {m["seq"]: m for m in out["messages"]}
        assert base64.b64decode(by_seq[0]["content_b64"]) == b""
        assert base64.b64decode(by_seq[1]["content_b64"]) == raw_bin
        assert by_seq[1]["type"] == "binary"
        assert by_seq[1]["text"] is not None
        assert by_seq[1]["total_bytes"] == len(raw_bin)
        import hashlib
        assert by_seq[1]["content_hash"] == hashlib.sha256(raw_bin).hexdigest()
        assert by_seq[2]["text"] == "plain"
    finally:
        if os.path.exists(path):
            os.remove(path)
