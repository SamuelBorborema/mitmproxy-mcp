import asyncio
import json
import pytest

from mcp.shared.subscriptions import ResourceUpdated
from mitmproxy_mcp.core.server import LIVE_FLOWS_URI, controller, mcp
from mitmproxy.test.tflow import tflow


@pytest.mark.asyncio
async def test_live_flow_resource_registered():
    """Resource flows://live must be discoverable via list_resources."""
    resources = await mcp.list_resources()
    uris = [str(r.uri) for r in resources]
    assert LIVE_FLOWS_URI in uris, f"Expected {LIVE_FLOWS_URI} in {uris}"
    # Check mime type
    match = next(r for r in resources if str(r.uri) == LIVE_FLOWS_URI)
    assert match.mime_type == "application/json"
    assert "Live" in (match.description or "")


@pytest.mark.asyncio
async def test_live_flow_resource_read_returns_json(monkeypatch):
    """Reading flows://live returns JSON array of flow summaries."""
    fake_flows = [
        {"id": "abc123", "url": "https://example.com/api", "method": "GET", "status_code": 200}
    ]

    monkeypatch.setattr(controller.recorder, "get_flow_summary", lambda limit=20: fake_flows)

    contents = await mcp.read_resource(LIVE_FLOWS_URI)
    # read_resource returns iterable of ReadResourceContents
    assert len(contents) == 1
    text = contents[0].content
    assert isinstance(text, str)
    data = json.loads(text)
    assert data == fake_flows
    assert contents[0].mime_type == "application/json"


@pytest.mark.asyncio
async def test_publishing_does_not_crash():
    """Direct bus publish for flows://live should not raise."""
    # Ensure publish does not crash even without subscribers
    await mcp._subscriptions.publish(ResourceUpdated(uri=LIVE_FLOWS_URI))
    # Also test with a subscriber
    events = []
    unsub = mcp._subscriptions.subscribe(lambda e: events.append(e))
    try:
        await mcp._subscriptions.publish(ResourceUpdated(uri=LIVE_FLOWS_URI))
        # InMemorySubscriptionBus delivers synchronously + checkpoint
        assert len(events) == 1
        assert isinstance(events[0], ResourceUpdated)
        assert events[0].uri == LIVE_FLOWS_URI
    finally:
        unsub()


@pytest.mark.asyncio
async def test_live_flow_notify_via_bus_subscription():
    """SubscriptionBus filtering for ResourceUpdated should deliver event."""
    from mcp.shared.subscriptions import event_matches
    from mcp_types import SubscriptionFilter

    filt = SubscriptionFilter(resource_subscriptions=[LIVE_FLOWS_URI])
    honored_uris = frozenset(filt.resource_subscriptions or [])

    captured = []

    def listener(event):
        if event_matches(filt, honored_uris, event):
            captured.append(event)

    unsub = mcp._subscriptions.subscribe(listener)
    try:
        await mcp._subscriptions.publish(ResourceUpdated(uri=LIVE_FLOWS_URI))
        assert len(captured) == 1
        # Publishing unrelated URI should not match filter
        await mcp._subscriptions.publish(ResourceUpdated(uri="flows://other"))
        assert len(captured) == 1
    finally:
        unsub()


def test_recorder_on_flow_wired():
    """Controller recorder should have on_flow callback wired."""
    assert controller.recorder.on_flow is not None
    # It should be the _notify_live_flow callable from server.py
    from mitmproxy_mcp.core.server import _notify_live_flow

    assert controller.recorder.on_flow is _notify_live_flow


def test_recorder_notify_does_not_crash_without_loop():
    """Calling _notify outside an event loop must not raise."""
    # Directly invoke the recorder's _notify (which calls on_flow)
    # Outside a loop, _notify_live_flow should silently return
    controller.recorder._notify()  # should not raise


@pytest.mark.asyncio
async def test_recorder_hook_triggers_publish(monkeypatch):
    """Saving a flow via recorder hooks should trigger bus publish."""
    events = []
    unsub = mcp._subscriptions.subscribe(lambda e: events.append(e))

    # Ensure recorder uses the wired callback inside async context
    try:
        flow = tflow()
        # Allow the flow through scope (default allows all)
        controller.recorder.request(flow)
        # Allow loop to process the create_task publish
        await asyncio.sleep(0.05)
        # At least one ResourceUpdated for flows://live should have been published
        assert any(isinstance(e, ResourceUpdated) and e.uri == LIVE_FLOWS_URI for e in events), (
            f"No ResourceUpdated event captured, events={events}"
        )
    finally:
        unsub()
        # Clean up db file created by tflow save
        try:
            controller.recorder.db.clear()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_live_flow_snapshot_limit(monkeypatch):
    """Resource should respect limit=20 when fetching snapshot."""
    called = {}

    def fake_get_summary(limit=20, offset=0):
        called["limit"] = limit
        return []

    monkeypatch.setattr(controller.recorder.db, "get_summary", fake_get_summary)
    # The resource implementation uses get_flow_summary which delegates to db.get_summary
    # Patch get_flow_summary as well to be safe
    monkeypatch.setattr(controller.recorder, "get_flow_summary", lambda limit=20: fake_get_summary(limit=limit))

    contents = await mcp.read_resource(LIVE_FLOWS_URI)
    assert called.get("limit") == 20
    assert json.loads(contents[0].content) == []
