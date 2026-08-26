import json
import time
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock
import pytest

from mitmproxy_mcp.core.server import controller, fuzz_endpoint
from mitmproxy_mcp.core.recorder import TrafficDB, SimpleResponse


@pytest.fixture
def tmp_db(monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    db = TrafficDB(db_path)
    monkeypatch.setattr(controller.recorder, "db", db)
    yield db


def _seed_flow(db: TrafficDB, flow_id="flow-baseline", response_body='{"result": "ok"}', status_code=200, request_body='{"key": "value"}'):
    ts = time.time()
    with db._get_conn() as conn:
        conn.execute(
            "INSERT INTO flows (id, url, method, status_code, request_headers, request_body, response_headers, response_body, timestamp, size) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                flow_id,
                "https://example.com/api/items",
                "GET",
                status_code,
                json.dumps([["Content-Type", "application/json"]]),
                request_body,
                json.dumps([["Content-Type", "application/json"]]),
                response_body,
                ts,
                len(response_body) if response_body else 0,
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
    if baseline_flow and baseline_flow.response and baseline_flow.response.body is not None:
        baseline_len = len(baseline_flow.response.body)
    else:
        baseline_len = 0
    assert baseline_len == 137


def test_fuzz_baseline_none_body(tmp_db):
    _seed_flow(tmp_db, response_body=None)
    flow = tmp_db.get_flow_object("flow-baseline")
    assert flow is not None
    assert flow.response is not None
    assert flow.response.body is None
    if flow.response.body is not None:
        baseline_len = len(flow.response.body)
    else:
        baseline_len = 0
    assert baseline_len == 0


def test_fuzz_baseline_empty_body(tmp_db):
    _seed_flow(tmp_db, response_body="")
    flow = tmp_db.get_flow_object("flow-baseline")
    assert flow.response.body == ""
    if flow.response.body is not None:
        baseline_len = len(flow.response.body)
    else:
        baseline_len = 0
    assert baseline_len == 0


def test_fuzz_baseline_no_response(tmp_db):
    ts = time.time()
    with tmp_db._get_conn() as conn:
        conn.execute(
            "INSERT INTO flows (id, url, method, status_code, request_headers, request_body, response_headers, response_body, timestamp, size) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                "flow-no-resp",
                "https://example.com/api/items",
                "GET",
                None,
                json.dumps([["Content-Type", "application/json"]]),
                "{}",
                None,
                None,
                ts,
                0,
            ),
        )
    flow = tmp_db.get_flow_object("flow-no-resp")
    assert flow.response is None


@pytest.mark.asyncio
async def test_fuzz_endpoint_calls_with_mocked_network(tmp_db, monkeypatch):
    body = "y" * 200
    _seed_flow(tmp_db, flow_id="flow-fuzz", response_body=body)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"ok response"

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    monkeypatch.setattr("mitmproxy_mcp.core.server.AsyncSession", lambda **kwargs: mock_client)

    result = await fuzz_endpoint(flow_id="flow-fuzz", target_param="q", param_type="query", payload_category="sqli", timeout=5.0)
    assert result["baseline_len"] == 200
    assert result["baseline_status"] == 200
    assert "anomalies" in result


@pytest.mark.asyncio
async def test_fuzz_endpoint_baseline_len_137_integration(tmp_db, monkeypatch):
    body = "x" * 137
    _seed_flow(tmp_db, flow_id="flow-137", response_body=body)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"same length response x"  # len similar, no anomaly for some payloads

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    monkeypatch.setattr("mitmproxy_mcp.core.server.AsyncSession", lambda **kwargs: mock_client)

    result = await fuzz_endpoint(flow_id="flow-137", target_param="id", param_type="query", payload_category="xss", timeout=5.0)
    assert result["baseline_len"] == 137
