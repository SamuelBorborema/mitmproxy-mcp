import pytest
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
