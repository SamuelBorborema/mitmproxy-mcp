import pytest
from unittest.mock import AsyncMock, MagicMock
from mitmproxy_mcp.core.server import replay_flow, controller


@pytest.mark.asyncio
async def test_replay_flow_errors_when_proxy_not_running(monkeypatch):
    monkeypatch.setattr(controller, "running", False)
    result = await replay_flow(flow_id="nonexistent-flow-id")
    assert result["status"] == "error"
    assert "isn't running" in result["message"]
    assert result["flow_id"] == "nonexistent-flow-id"


@pytest.mark.asyncio
async def test_replay_request_precheck_before_flow_lookup(monkeypatch):
    monkeypatch.setattr(controller, "running", False)

    def _boom(flow_id):
        raise AssertionError("flow lookup should not happen when proxy is stopped")

    monkeypatch.setattr(controller.recorder, "get_flow_detail", _boom)
    msg = await controller.replay_request("any-flow-id")
    assert msg == "The proxy isn't running. Start it first with start_proxy."


@pytest.mark.asyncio
async def test_replay_flow_not_blocked_when_running(monkeypatch):
    monkeypatch.setattr(controller, "running", True)
    monkeypatch.setattr(controller, "port", 8080)

    def fake_get_detail(flow_id):
        return None

    monkeypatch.setattr(controller.recorder, "get_flow_detail", fake_get_detail)
    result = await replay_flow(flow_id="missing-id-when-running")
    assert result["status"] == "error"
    assert "Couldn't find" in result["message"]
    assert "isn't running" not in result["message"].lower()


@pytest.mark.asyncio
async def test_replay_flow_case_insensitive_error_detection(monkeypatch):
    monkeypatch.setattr(controller, "running", False)
    result = await replay_flow(flow_id="any")
    assert result["status"] == "error"
    assert "isn't running" in result["message"].lower()


@pytest.mark.asyncio
async def test_replay_request_does_not_call_network_when_stopped(monkeypatch):
    monkeypatch.setattr(controller, "running", False)
    called = {}

    def fake_session(**kwargs):
        called["called"] = True
        raise AssertionError("AsyncSession should not be instantiated when proxy stopped")

    monkeypatch.setattr("mitmproxy_mcp.core.server.AsyncSession", fake_session)
    monkeypatch.setattr(controller.recorder, "get_flow_detail", lambda fid: {"request": {"url": "https://example.com", "method": "GET", "headers": {}, "body_preview": None}})

    msg = await controller.replay_request("test-flow")
    assert "isn't running" in msg
    assert "called" not in called
