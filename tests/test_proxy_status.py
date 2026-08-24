import os
import time
import pytest
from mitmproxy_mcp.core.server import proxy_status, controller, mcp


@pytest.mark.asyncio
async def test_proxy_status_returns_dict():
    result = await proxy_status()
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_proxy_status_has_expected_keys():
    result = await proxy_status()
    expected_keys = {
        "running",
        "host",
        "port",
        "uptime_seconds",
        "flow_count",
        "db_path",
        "db_size_bytes",
        "active_rules_count",
        "scope_domains",
        "upstream_proxy",
        "auto_start",
        "default_host",
        "default_port",
    }
    missing = expected_keys - set(result.keys())
    assert not missing, f"Missing keys in proxy_status: {sorted(missing)}"


@pytest.mark.asyncio
async def test_proxy_status_flow_count_is_int():
    result = await proxy_status()
    assert isinstance(result["flow_count"], int)
    assert result["flow_count"] >= 0


@pytest.mark.asyncio
async def test_proxy_status_field_types():
    result = await proxy_status()
    assert isinstance(result["running"], bool)
    assert isinstance(result["host"], str)
    assert isinstance(result["port"], int)
    assert isinstance(result["db_path"], str)
    # db_size_bytes is int when file exists or 0, or None on error
    assert isinstance(result["db_size_bytes"], int) or result["db_size_bytes"] is None
    assert isinstance(result["active_rules_count"], int)
    assert isinstance(result["scope_domains"], list)
    assert isinstance(result["auto_start"], bool)
    assert isinstance(result["default_host"], str)
    assert isinstance(result["default_port"], int)
    # uptime_seconds is None when not running, float when running
    assert result["uptime_seconds"] is None or isinstance(result["uptime_seconds"], float)


@pytest.mark.asyncio
async def test_proxy_status_uptime_none_when_stopped():
    # Ensure stopped state
    controller.running = False
    controller.started_at = None
    result = await proxy_status()
    assert result["running"] is False
    assert result["uptime_seconds"] is None


@pytest.mark.asyncio
async def test_proxy_status_uptime_when_running(monkeypatch):
    # Simulate running state with started_at set to 5 seconds ago
    monkeypatch.setattr(controller, "running", True)
    monkeypatch.setattr(controller, "started_at", time.monotonic() - 5)
    result = await proxy_status()
    assert result["running"] is True
    assert isinstance(result["uptime_seconds"], float)
    assert result["uptime_seconds"] >= 4.5  # allow small timing variance
    assert result["uptime_seconds"] < 20


@pytest.mark.asyncio
async def test_proxy_status_active_rules_count_matches_interceptor():
    # Ensure interceptor rules count is reflected
    from mitmproxy_mcp.models import InterceptionRule

    # Save original rules
    original_rules = dict(controller.interceptor.rules)
    original_patterns = dict(controller.interceptor._compiled_patterns)
    try:
        controller.interceptor.clear_rules()
        result_empty = await proxy_status()
        assert result_empty["active_rules_count"] == 0

        rule = InterceptionRule(id="test-proxy-status", action_type="block")
        controller.interceptor.add_rule(rule)
        result_one = await proxy_status()
        assert result_one["active_rules_count"] == 1
    finally:
        controller.interceptor.rules.clear()
        controller.interceptor._compiled_patterns.clear()
        controller.interceptor.rules.update(original_rules)
        controller.interceptor._compiled_patterns.update(original_patterns)


@pytest.mark.asyncio
async def test_proxy_status_db_size_bytes_matches_file():
    result = await proxy_status()
    db_path = result["db_path"]
    if os.path.exists(db_path):
        assert result["db_size_bytes"] == os.path.getsize(db_path)
    else:
        assert result["db_size_bytes"] == 0


@pytest.mark.asyncio
async def test_proxy_status_tool_annotations_readonly():
    tools = await mcp.list_tools()
    proxy_tool = next((t for t in tools if t.name == "proxy_status"), None)
    assert proxy_tool is not None, "proxy_status tool not found in mcp.list_tools()"
    assert proxy_tool.annotations is not None
    assert proxy_tool.annotations.read_only_hint is True
