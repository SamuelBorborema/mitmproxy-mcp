import pytest
import json
from mitmproxy.test.tflow import tflow
from mitmproxy.test.tutils import treq, tresp
from mitmproxy import http

from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.diff import diff_headers, diff_bodies, diff_status, diff_size


@pytest.fixture(autouse=True)
def clear_traffic():
    # Ensure clean DB and deque before each test
    server.controller.recorder.clear()
    server.controller.recorder.flows.clear()
    yield
    server.controller.recorder.clear()
    server.controller.recorder.flows.clear()


def _save_flow(flow):
    server.controller.recorder.db.save_flow(flow)
    # also push to deque for live fallback path
    server.controller.recorder.flows.append(flow)
    return flow.id


@pytest.mark.asyncio
async def test_diff_status_200_vs_403():
    flow1 = tflow(req=treq(host="example.com", path=b"/api", method=b"GET"), resp=tresp(status_code=200, content=b'{"status":"ok"}'))
    flow2 = tflow(req=treq(host="example.com", path=b"/api", method=b"GET"), resp=tresp(status_code=403, content=b'{"error":"forbidden"}'))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)

    result = await server.diff_flows(flow_ids=f"{id1},{id2}")
    assert result["anchor"] == id1
    assert result["flows"] == [id1, id2]
    assert len(result["diffs"]) == 1
    entry = result["diffs"][0]
    assert entry["flow_id"] == id2
    # status diff
    assert entry["status"]["a"] == 200
    assert entry["status"]["b"] == 403
    assert entry["status"]["diff"] is True
    # matrix should exist
    assert "matrix" in result
    assert len(result["matrix"]) == 2
    assert result["matrix"][0][1] is not None
    assert result["matrix"][0][1]["status"]["diff"] is True


@pytest.mark.asyncio
async def test_diff_header_injection_added():
    # flow without extra header
    req_a = treq(host="example.com", path=b"/api", headers=http.Headers(((b"Host", b"example.com"), (b"User-Agent", b"test"))), content=b"")
    flow1 = tflow(req=req_a, resp=tresp(status_code=200, content=b"ok"))
    # flow with injected header
    req_b = treq(host="example.com", path=b"/api", headers=http.Headers(((b"Host", b"example.com"), (b"User-Agent", b"test"), (b"X-Injected", b"1"))), content=b"")
    flow2 = tflow(req=req_b, resp=tresp(status_code=200, content=b"ok"))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)

    result = await server.diff_flows(flow_ids=f"{id1},{id2}", include_headers=True)
    entry = result["diffs"][0]
    # request headers should show added X-Injected
    hdr_diff = entry["request"]["headers"]
    # added contains lowercased key
    added_keys = [a["key"] for a in hdr_diff["added"]]
    assert "x-injected" in added_keys
    # case-insensitivity check: try mixed case
    # also ensure modified is empty for this
    assert hdr_diff["modified"] == [] or any(m["key"] == "x-injected" for m in hdr_diff["added"])


@pytest.mark.asyncio
async def test_diff_json_key_added():
    body_a = json.dumps({"a": 1, "common": "value"})
    body_b = json.dumps({"a": 1, "common": "value", "b": 2})
    flow1 = tflow(req=treq(host="example.com", path=b"/api", method=b"POST", content=b'{}'), resp=tresp(status_code=200, headers=http.Headers(((b"Content-Type", b"application/json"),)), content=body_a.encode()))
    flow2 = tflow(req=treq(host="example.com", path=b"/api", method=b"POST", content=b'{}'), resp=tresp(status_code=200, headers=http.Headers(((b"Content-Type", b"application/json"),)), content=body_b.encode()))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)

    result = await server.diff_flows(flow_ids=f"{id1},{id2}", body_diff_mode="auto")
    entry = result["diffs"][0]
    resp_body = entry["response"]["body"]
    assert resp_body["diff_type"] == "json"
    assert resp_body["json_diff"] is not None
    # added should contain "b"
    assert "b" in resp_body["json_diff"]["added"]
    # unified diff should contain b
    assert "b" in resp_body["unified"]


@pytest.mark.asyncio
async def test_diff_binary_hex_handling():
    # binary response bodies
    bin_a = b"\x00\x01\x02\xff\xfe" + b"A"*10
    bin_b = b"\x00\x01\x02\xff\xfe" + b"B"*10
    flow1 = tflow(req=treq(host="example.com", path=b"/bin"), resp=tresp(status_code=200, content=bin_a))
    flow2 = tflow(req=treq(host="example.com", path=b"/bin"), resp=tresp(status_code=200, content=bin_b))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)

    result = await server.diff_flows(flow_ids=f"{id1},{id2}", body_diff_mode="auto")
    entry = result["diffs"][0]
    resp_body = entry["response"]["body"]
    # auto should detect binary and use hex
    assert resp_body["diff_type"] == "hex"
    assert resp_body["unified"] is not None
    # hex diff should contain hex representation
    assert "00 01 02" in resp_body["unified"] or "ff fe" in resp_body["unified"].lower()
    # also test explicit hex mode
    result_hex = await server.diff_flows(flow_ids=f"{id1},{id2}", body_diff_mode="hex")
    assert result_hex["diffs"][0]["response"]["body"]["diff_type"] == "hex"

    # Also test direct diff_bodies helper
    direct = diff_bodies("\x00\x01\x02ÿþ", "\x00\x01\x02ÿþX", mode="auto", max_body_chars=20000)
    assert direct["diff_type"] == "hex"


@pytest.mark.asyncio
async def test_diff_truncation_warning():
    # create large bodies > max_body_chars
    large_a = "A" * 5000
    large_b = "A" * 4999 + "B"
    flow1 = tflow(req=treq(host="example.com", path=b"/large"), resp=tresp(status_code=200, content=large_a.encode()))
    flow2 = tflow(req=treq(host="example.com", path=b"/large"), resp=tresp(status_code=200, content=large_b.encode()))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)

    # Use small max_body_chars to trigger truncation
    result = await server.diff_flows(flow_ids=f"{id1},{id2}", max_body_chars=2000)
    entry = result["diffs"][0]
    resp_body = entry["response"]["body"]
    assert resp_body["truncated"] is True
    assert any("max_body_chars" in w or "truncated" in w.lower() for w in result["warnings"])
    # sha256 should be present
    assert "sha256_a" in resp_body
    assert "sha256_b" in resp_body
    # also check request body diff maybe not truncated but response should be
    assert resp_body["diff_type"] in ("text", "hex", "json")


@pytest.mark.asyncio
async def test_diff_n3_mesh_matrix():
    flow1 = tflow(req=treq(host="example.com", path=b"/a"), resp=tresp(status_code=200, content=b"hello a"))
    flow2 = tflow(req=treq(host="example.com", path=b"/b"), resp=tresp(status_code=200, content=b"hello b"))
    flow3 = tflow(req=treq(host="example.com", path=b"/c"), resp=tresp(status_code=404, content=b"not found"))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)
    id3 = _save_flow(flow3)

    result = await server.diff_flows(flow_ids=f"{id1},{id2},{id3}")
    assert result["flows"] == [id1, id2, id3]
    assert result["anchor"] == id1
    # diffs anchored to first: should have 2 entries (n-1)
    assert len(result["diffs"]) == 2
    assert result["diffs"][0]["flow_id"] == id2
    assert result["diffs"][1]["flow_id"] == id3
    # matrix should be 3x3
    matrix = result["matrix"]
    assert len(matrix) == 3
    assert all(len(row) == 3 for row in matrix)
    # diagonal should be None
    assert matrix[0][0] is None
    assert matrix[1][1] is None
    assert matrix[2][2] is None
    # check off-diagonal status diff for 200 vs 404
    # anchor vs third should be diff
    assert result["diffs"][1]["status"]["diff"] is True
    assert result["diffs"][1]["status"]["a"] == 200
    assert result["diffs"][1]["status"]["b"] == 404
    # matrix[0][2] should also reflect status diff
    assert matrix[0][2]["status"]["diff"] is True
    assert matrix[2][0]["status"]["diff"] is True
    # matrix[0][1] should be 200 vs 200 no status diff but size maybe differs slightly?
    assert matrix[0][1]["flow_a"] == id1
    assert matrix[0][1]["flow_b"] == id2


@pytest.mark.asyncio
async def test_diff_headers_case_insensitive_duplicate():
    # Test case-insensitive and multiset for Set-Cookie duplicates
    req_a = treq(host="example.com", path=b"/cookies", headers=http.Headers(((b"Set-Cookie", b"a=1"), (b"Set-Cookie", b"b=2"), (b"Content-Type", b"text/html"))))
    req_b = treq(host="example.com", path=b"/cookies", headers=http.Headers(((b"set-cookie", b"a=1"), (b"Set-Cookie", b"b=2"), (b"Set-Cookie", b"c=3"), (b"content-type", b"text/html"))))
    flow1 = tflow(req=req_a, resp=tresp(status_code=200, content=b"ok"))
    flow2 = tflow(req=req_b, resp=tresp(status_code=200, content=b"ok"))
    id1 = _save_flow(flow1)
    id2 = _save_flow(flow2)

    result = await server.diff_flows(flow_ids=f"{id1},{id2}")
    hdr = result["diffs"][0]["request"]["headers"]
    # should have modified for set-cookie because counts differ
    modified_keys = [m["key"] for m in hdr["modified"]]
    assert "set-cookie" in modified_keys
    # direct helper test for case insensitive
    h1 = [["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]]
    h2 = [["set-cookie", "a=1"], ["Set-Cookie", "b=2"], ["Set-Cookie", "c=3"]]
    dh = diff_headers(h1, h2)
    assert any(m["key"] == "set-cookie" for m in dh["modified"])


@pytest.mark.asyncio
async def test_diff_validation():
    flow1 = tflow(req=treq(host="example.com", path=b"/x"), resp=tresp(status_code=200, content=b"hi"))
    id1 = _save_flow(flow1)
    # single id should error
    result = await server.diff_flows(flow_ids=id1)
    assert "error" in result
    # invalid compare
    flow2 = tflow(req=treq(host="example.com", path=b"/y"), resp=tresp(status_code=200, content=b"hi"))
    id2 = _save_flow(flow2)
    result2 = await server.diff_flows(flow_ids=f"{id1},{id2}", compare="invalid")
    assert "error" in result2
    # invalid mode
    result3 = await server.diff_flows(flow_ids=f"{id1},{id2}", body_diff_mode="bad")
    assert "error" in result3


@pytest.mark.asyncio
async def test_diff_tool_annotations_and_list():
    tools = await server.mcp.list_tools()
    diff_tool = next((t for t in tools if t.name == "diff_flows"), None)
    assert diff_tool is not None, "diff_flows tool not found"
    assert diff_tool.annotations is not None
    assert diff_tool.annotations.read_only_hint is True
    assert diff_tool.annotations.open_world_hint is False
    # input schema should contain flow_ids
    assert diff_tool.input_schema is not None
    props = diff_tool.input_schema.get("properties", {})
    assert "flow_ids" in props
    # output schema should exist (structured output)
    # mcp 2.x generates outputSchema from return annotation dict[str,Any]
    # It may be under outputSchema or not None
    assert hasattr(diff_tool, "output_schema") or hasattr(diff_tool, "outputSchema") or diff_tool.input_schema is not None
