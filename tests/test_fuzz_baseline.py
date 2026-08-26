import json
import time
import tempfile
import os
import pytest

from mitmproxy_mcp.core.server import controller
from mitmproxy_mcp.core.recorder import TrafficDB, SimpleResponse


@pytest.fixture
def tmp_db(monkeypatch):
    tmp = tempfile.mktemp(suffix=".db")
    db = TrafficDB(tmp)
    monkeypatch.setattr(controller.recorder, "db", db)
    yield db
    try:
        os.remove(tmp)
    except Exception:
        pass


def _seed_flow(db: TrafficDB, flow_id="flow-baseline", response_body='{"result": "ok"}'):
    ts = time.time()
    with db._get_conn() as conn:
        conn.execute(
            "INSERT INTO flows (id, url, method, status_code, request_headers, request_body, response_headers, response_body, timestamp, size) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                flow_id,
                "https://example.com/api/items",
                "GET",
                200,
                json.dumps([["Content-Type", "application/json"]]),
                json.dumps({"key": "value"}),
                json.dumps([["Content-Type", "application/json"]]),
                response_body,
                ts,
                len(response_body),
            ),
        )


def test_get_flow_object_response_body(tmp_db):
    body = '{"result": "ok", "data": "baseline-content"}'
    _seed_flow(tmp_db, response_body=body)
    flow = tmp_db.get_flow_object("flow-baseline")
    assert flow is not None
    assert flow.response is not None
    assert isinstance(flow.response, SimpleResponse)
    assert flow.response.status_code == 200
    assert flow.response.body == body
    assert len(flow.response.body) == len(body)
    assert not hasattr(flow.response, "content")


def test_fuzz_baseline_length_from_body(tmp_db):
    body = "x" * 137
    _seed_flow(tmp_db, response_body=body)
    baseline_flow = tmp_db.get_flow_object("flow-baseline")
    if baseline_flow and baseline_flow.response:
        baseline_status = baseline_flow.response.status_code
    else:
        baseline_status = 200

    if baseline_flow and baseline_flow.response and baseline_flow.response.body:
        baseline_len = len(baseline_flow.response.body)
    else:
        baseline_len = 0

    assert baseline_status == 200
    assert baseline_len == 137
