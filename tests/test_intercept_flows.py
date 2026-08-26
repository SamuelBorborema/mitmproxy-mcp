from mitmproxy.test import tutils
from mitmproxy.test.tflow import tflow

from mitmproxy_mcp.core.interceptor import TrafficInterceptor


def test_set_intercept_filter_valid():
    interceptor = TrafficInterceptor()
    assert interceptor.set_intercept_filter("example.com") is True
    assert interceptor.intercept_filter == "example.com"


def test_set_intercept_filter_invalid():
    interceptor = TrafficInterceptor()
    assert interceptor.set_intercept_filter("(") is False
    assert interceptor.intercept_filter is None


def test_set_intercept_filter_disable():
    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("example.com")
    assert interceptor.set_intercept_filter(None) is True
    assert interceptor.intercept_filter is None
    assert interceptor.set_intercept_filter("") is True
    assert interceptor.intercept_filter is None


def test_matching_flow_is_intercepted():
    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("http://example.com")
    f = tflow(req=tutils.treq(host="example.com", port=80))
    interceptor.request(f)
    assert f.id in interceptor.intercepted_flows
    assert f.intercepted

    flows = interceptor.get_intercepted_flows()
    assert len(flows) == 1
    assert flows[0]["id"] == f.id
    assert flows[0]["status"] == "intercepted"
    assert flows[0]["url"] == f.request.url
    assert flows[0]["method"] == f.request.method


def test_non_matching_flow_passes_through():
    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("http://other-host.example")
    f = tflow(req=tutils.treq(host="example.com", port=80))
    interceptor.request(f)
    assert f.id not in interceptor.intercepted_flows
    assert not f.intercepted


def test_intercepted_flow_skips_rules():
    from mitmproxy_mcp.models import InterceptionRule

    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("http://example.com")
    interceptor.add_rule(
        InterceptionRule(
            id="h1",
            action_type="inject_header",
            key="X-Test",
            value="FoundIt",
            resource_type="request",
        )
    )
    f = tflow(req=tutils.treq(host="example.com", port=80))
    interceptor.request(f)
    assert f.id in interceptor.intercepted_flows
    assert "X-Test" not in f.request.headers


def test_resume_flow():
    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("http://example.com")
    f = tflow(req=tutils.treq(host="example.com", port=80))
    interceptor.request(f)
    assert interceptor.resume_flow(f.id) is True
    assert f.id not in interceptor.intercepted_flows
    assert not f.intercepted
    assert interceptor.resume_flow(f.id) is False


def test_drop_flow():
    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("http://example.com")
    f = tflow(req=tutils.treq(host="example.com", port=80))
    interceptor.request(f)
    assert interceptor.drop_flow(f.id) is True
    assert f.id not in interceptor.intercepted_flows
    assert not f.intercepted
    assert not f.live
    assert interceptor.drop_flow(f.id) is False


def test_resume_all():
    interceptor = TrafficInterceptor()
    interceptor.set_intercept_filter("http://example.com")
    flows = [tflow(req=tutils.treq(host="example.com", port=80)) for _ in range(3)]
    for f in flows:
        interceptor.request(f)
    assert len(interceptor.intercepted_flows) == 3
    assert interceptor.resume_all() == 3
    assert len(interceptor.intercepted_flows) == 0
    assert all(not f.intercepted for f in flows)
    assert interceptor.resume_all() == 0
