import asyncio
import json
import os
import zlib
from pathlib import Path

import pytest
from mitmproxy import connection, http

from mitmproxy_mcp.core.server import controller, export_har, load_traffic_file


def _make_flow(url: str, resp_body: bytes = b"hello", ctype: bytes = b"text/plain", req_body: bytes = b"", method: str = "GET"):
    client = connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0), timestamp_start=1234567890.0)
    server = connection.Server(address=("example.com", 80))
    flow = http.HTTPFlow(client, server, live=False)
    flow.request = http.Request.make(method, url, content=req_body)
    flow.request.timestamp_start = 1234567890.0
    flow.request.timestamp_end = 1234567890.0
    flow.response = http.Response.make(200, content=resp_body, headers=[(b"content-type", ctype)])
    flow.response.timestamp_start = 1234567890.0
    flow.response.timestamp_end = 1234567890.1
    return flow


@pytest.mark.asyncio
async def test_round_trip_count_preserved():
    controller.recorder.clear()
    f1 = _make_flow("http://example.com/a", b"one")
    f2 = _make_flow("http://example.com/b", b"two")
    f3 = _make_flow("http://other.com/c", b"three")
    for f in [f1, f2, f3]:
        controller.recorder.db.save_flow(f)
    out = Path("test_roundtrip.har")
    if out.exists():
        out.unlink()
    try:
        res = await export_har(str(out))
        assert res["status"] == "ok"
        assert res["entries"] == 3
        assert out.exists()
        har = json.loads(out.read_text())
        assert len(har["log"]["entries"]) == 3
        # re-import via load_traffic_file
        controller.recorder.clear()
        res2 = await load_traffic_file(str(out))
        assert res2["status"] == "ok"
        assert res2["imported"] == 3
    finally:
        if out.exists():
            out.unlink()
        controller.recorder.clear()


@pytest.mark.asyncio
async def test_binary_base64_handling():
    controller.recorder.clear()
    binary = b"\x89PNG\x00\x01\xff\xfe\x80"
    flow = _make_flow("http://example.com/binary", binary, ctype=b"image/png")
    controller.recorder.db.save_flow(flow)
    out = Path("test_binary.har")
    if out.exists():
        out.unlink()
    try:
        res = await export_har(str(out))
        assert res["status"] == "ok"
        assert res["entries"] == 1
        har = json.loads(out.read_text())
        entry = har["log"]["entries"][0]
        content = entry["response"]["content"]
        # SaveHar encodes binary as base64
        assert content.get("encoding") == "base64"
        # round-trip should preserve
        controller.recorder.clear()
        res2 = await load_traffic_file(str(out))
        assert res2["imported"] == 1
    finally:
        if out.exists():
            out.unlink()
        controller.recorder.clear()


@pytest.mark.asyncio
async def test_path_traversal_blocked():
    # should be blocked even with traversal
    res = await export_har("../../tmp/outside.har")
    assert res["status"] == "error"
    assert "Security Error" in res["message"]
    assert "Access denied" in res["message"]
    # also absolute outside
    res2 = await export_har("/tmp/outside2.har")
    assert res2["status"] == "error"
    assert "Security Error" in res2["message"]


@pytest.mark.asyncio
async def test_domain_filter():
    controller.recorder.clear()
    f1 = _make_flow("http://example.com/a", b"one")
    f2 = _make_flow("http://example.com/b", b"two")
    f3 = _make_flow("http://other.com/c", b"three")
    for f in [f1, f2, f3]:
        controller.recorder.db.save_flow(f)
    out = Path("test_domain.har")
    if out.exists():
        out.unlink()
    try:
        res = await export_har(str(out), domain="example.com")
        assert res["status"] == "ok"
        assert res["entries"] == 2
        har = json.loads(out.read_text())
        assert len(har["log"]["entries"]) == 2
        for e in har["log"]["entries"]:
            assert "example.com" in e["request"]["url"]
        assert res["filter"]["domain"] == "example.com"
    finally:
        if out.exists():
            out.unlink()
        controller.recorder.clear()


@pytest.mark.asyncio
async def test_limit_filter():
    controller.recorder.clear()
    for i in range(5):
        f = _make_flow(f"http://example.com/{i}", f"body{i}".encode())
        # Ensure distinct timestamps
        f.request.timestamp_start = 1234567890.0 + i
        controller.recorder.db.save_flow(f)
    out = Path("test_limit.har")
    if out.exists():
        out.unlink()
    try:
        res = await export_har(str(out), limit=2)
        assert res["status"] == "ok"
        assert res["entries"] == 2
        har = json.loads(out.read_text())
        assert len(har["log"]["entries"]) == 2
        assert res["filter"]["limit"] == 2
    finally:
        if out.exists():
            out.unlink()
        controller.recorder.clear()


@pytest.mark.asyncio
async def test_compress_flag():
    controller.recorder.clear()
    f1 = _make_flow("http://example.com/a", b"hello world")
    controller.recorder.db.save_flow(f1)
    # plain
    out_plain = Path("test_compress_plain.har")
    out_compressed = Path("test_compress.har")
    out_zhar = Path("test_auto.zhar")
    for p in [out_plain, out_compressed, out_zhar]:
        if p.exists():
            p.unlink()
    try:
        # compress flag
        res = await export_har(str(out_compressed), compress=True)
        assert res["status"] == "ok"
        assert res["entries"] == 1
        data = out_compressed.read_bytes()
        # should be zlib compressed
        decompressed = zlib.decompress(data)
        har = json.loads(decompressed)
        assert len(har["log"]["entries"]) == 1

        # .zhar auto compress
        res2 = await export_har(str(out_zhar))
        assert res2["status"] == "ok"
        data2 = out_zhar.read_bytes()
        decompressed2 = zlib.decompress(data2)
        har2 = json.loads(decompressed2)
        assert len(har2["log"]["entries"]) == 1

        # ensure plain is not compressed
        res3 = await export_har(str(out_plain))
        assert res3["status"] == "ok"
        plain_data = out_plain.read_bytes()
        # plain should be valid JSON directly
        har3 = json.loads(plain_data)
        assert len(har3["log"]["entries"]) == 1
        # compressed bytes should be smaller or at least different
        assert res["bytes"] == len(data)
    finally:
        for p in [out_plain, out_compressed, out_zhar]:
            if p.exists():
                p.unlink()
        controller.recorder.clear()


@pytest.mark.asyncio
async def test_flow_ids_filter():
    controller.recorder.clear()
    f1 = _make_flow("http://example.com/a", b"one")
    f2 = _make_flow("http://example.com/b", b"two")
    controller.recorder.db.save_flow(f1)
    controller.recorder.db.save_flow(f2)
    ids = [row[0] for row in controller.recorder.db._get_conn().execute("SELECT id FROM flows").fetchall()]
    assert len(ids) == 2
    out = Path("test_flow_ids.har")
    if out.exists():
        out.unlink()
    try:
        res = await export_har(str(out), flow_ids=ids[0])
        assert res["status"] == "ok"
        assert res["entries"] == 1
        har = json.loads(out.read_text())
        assert len(har["log"]["entries"]) == 1
        # csv multiple
        out2 = Path("test_flow_ids2.har")
        if out2.exists():
            out2.unlink()
        res2 = await export_har(str(out2), flow_ids=",".join(ids))
        assert res2["entries"] == 2
        if out2.exists():
            out2.unlink()
    finally:
        if out.exists():
            out.unlink()
        controller.recorder.clear()
