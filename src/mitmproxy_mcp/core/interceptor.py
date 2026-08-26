import logging
from typing import Any, Dict, List, Optional
import re2
from mitmproxy import http
from ..models import InterceptionRule
from .utils import get_safe_text

logger = logging.getLogger("mcp_mitm")


class TrafficInterceptor:
    """Applies dynamic rules to modify traffic on the fly."""

    def __init__(self):
        self.rules: Dict[str, InterceptionRule] = {}
        self._compiled_patterns: Dict[str, Dict[str, Any]] = {}
        self.intercept_filter: Optional[str] = None
        self._intercept_pattern = None
        self.intercepted_flows: Dict[str, http.HTTPFlow] = {}

    def add_rule(self, rule: InterceptionRule) -> bool:
        patterns = {}
        try:
            if rule.url_pattern:
                patterns["url"] = re2.compile(rule.url_pattern)
            if rule.search_pattern:
                patterns["search"] = re2.compile(rule.search_pattern)
        except re2.error as e:
            logger.warning("Failed to compile regex for rule %s: %s", rule.id, e)
            return False

        self.rules[rule.id] = rule
        self._compiled_patterns[rule.id] = patterns
        logger.info("Added interception rule: %s", rule)
        return True

    def remove_rule(self, rule_id: str):
        if rule_id in self.rules:
            del self.rules[rule_id]
        if rule_id in self._compiled_patterns:
            del self._compiled_patterns[rule_id]

    def clear_rules(self):
        self.rules.clear()
        self._compiled_patterns.clear()

    def get_active_rules(self):
        return list(self.rules.values())

    def set_intercept_filter(self, pattern: Optional[str]) -> bool:
        if not pattern:
            self.intercept_filter = None
            self._intercept_pattern = None
            return True
        try:
            self._intercept_pattern = re2.compile(pattern)
        except re2.error as e:
            logger.warning("Failed to compile intercept filter: %s", e)
            return False
        self.intercept_filter = pattern
        return True

    def get_intercepted_flows(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": flow_id,
                "method": flow.request.method,
                "url": flow.request.url,
                "status": "intercepted",
                "timestamp": flow.request.timestamp_start,
            }
            for flow_id, flow in self.intercepted_flows.items()
        ]

    def resume_flow(self, flow_id: str) -> bool:
        flow = self.intercepted_flows.pop(flow_id, None)
        if flow is None:
            return False
        flow.resume()
        return True

    def resume_all(self) -> int:
        count = 0
        for flow in self.intercepted_flows.values():
            flow.resume()
            count += 1
        self.intercepted_flows.clear()
        return count

    def drop_flow(self, flow_id: str) -> bool:
        flow = self.intercepted_flows.pop(flow_id, None)
        if flow is None:
            return False
        flow.kill()
        return True

    def request(self, flow: http.HTTPFlow):
        if self.intercept_filter and self._intercept_pattern:
            if self._intercept_pattern.search(flow.request.url):
                flow.intercept()
                self.intercepted_flows[flow.id] = flow
                return
        self._apply_rules(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self._apply_rules(flow, "response")

    def _apply_rules(self, flow: http.HTTPFlow, phase: str):
        message = getattr(flow, phase)
        if not message:
            return

        for rule in self.rules.values():
            if not rule.active or rule.resource_type != phase:
                continue

            if rule.method and flow.request.method != rule.method:
                continue

            compiled = self._compiled_patterns.get(rule.id, {})
            url_pattern = compiled.get("url")

            if url_pattern:
                if not url_pattern.search(flow.request.url):
                    continue

            try:
                if (
                    rule.action_type == "inject_header"
                    and rule.key
                    and rule.value
                ):
                    message.headers[rule.key] = rule.value
                    logger.info(
                        "Injected header: '%s' using: '%s'",
                        rule.key,
                        rule.id,
                    )

                elif (
                    rule.action_type == "replace_body"
                    and rule.search_pattern
                    and rule.value
                ):
                    text = get_safe_text(message)
                    if text is not None:
                        search_pattern = compiled.get("search")
                        if search_pattern:
                            new_text = search_pattern.sub(rule.value, text)
                        else:
                            continue
                        message.text = new_text
                        logger.info(
                            "Body modified by rule: '%s'",
                            rule.id,
                        )

                elif rule.action_type == "block":
                    flow.kill()
                    logger.info(
                        "Request blocked per rule: '%s'",
                        rule.id,
                    )

            except Exception as e:
                logger.error(
                    "[ERROR] Couldn't apply rule:  '%s': %s",
                    rule.id,
                    e,
                )
