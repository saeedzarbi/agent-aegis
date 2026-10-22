"""Baseline behavior before sensitive-data policy is enabled."""

from aegis.core.models import ToolCallRequest
from aegis.core.policy import Policy
from aegis.guard.pipeline import GuardPipeline


def test_pii_in_user_input_allowed_when_sensitive_disabled():
    guard = GuardPipeline(Policy.default_demo())
    text = "Contact me at patron@bank.example and card 4111111111111111"
    decision = guard.inspect_user_input("s1", "default", text)
    assert decision.allowed
    assert not any(s.rule_id.startswith("sensitive_") for s in decision.signals)


def test_pii_in_tool_arguments_allowed_when_sensitive_disabled():
    guard = GuardPipeline(Policy.default_demo())
    request = ToolCallRequest(
        session_id="s1",
        tool_name="search_docs",
        arguments={"query": "account 078-05-1120 for user@corp.com"},
        user_message="lookup",
    )
    decision = guard.inspect_tool_call(request)
    assert decision.allowed
    assert not any(s.rule_id.startswith("sensitive_") for s in decision.signals)
