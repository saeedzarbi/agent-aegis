"""Sensitive-data policy enabled (Phase 1)."""

from aegis.core.models import ToolCallRequest
from aegis.core.policy import Policy, SensitiveDataPolicy
from aegis.guard.pipeline import GuardPipeline


def _policy_block() -> Policy:
    base = Policy.default_demo()
    return base.model_copy(
        update={
            "sensitive_data": SensitiveDataPolicy(enabled=True, mode="block"),
        }
    )


def _policy_mask() -> Policy:
    base = Policy.default_demo()
    return base.model_copy(
        update={
            "sensitive_data": SensitiveDataPolicy(enabled=True, mode="mask"),
        }
    )


def test_blocks_payment_card_in_user_input():
    guard = GuardPipeline(_policy_block())
    decision = guard.inspect_user_input(
        "s1",
        "default",
        "charge card 4111111111111111 today",
    )
    assert not decision.allowed
    assert any(s.rule_id == "sensitive_payment_card" for s in decision.signals)


def test_masks_email_in_user_input():
    guard = GuardPipeline(_policy_mask())
    text = "reach me at user@bank.example"
    decision = guard.inspect_user_input("s1", "default", text)
    assert decision.allowed
    assert decision.sanitized_user_text is not None
    assert "user@bank.example" not in decision.sanitized_user_text
    assert "[REDACTED:EMAIL]" in decision.sanitized_user_text


def test_blocks_ssn_in_tool_arguments():
    guard = GuardPipeline(_policy_block())
    request = ToolCallRequest(
        session_id="s1",
        tool_name="search_docs",
        arguments={"query": "tax id 078-05-1120"},
        user_message="search",
    )
    decision = guard.inspect_tool_call(request)
    assert not decision.allowed
    assert any(s.rule_id == "sensitive_ssn" for s in decision.signals)


def test_masks_email_in_tool_arguments():
    guard = GuardPipeline(_policy_mask())
    request = ToolCallRequest(
        session_id="s1",
        tool_name="search_docs",
        arguments={"query": "contact alice@example.com"},
        user_message="search",
    )
    decision = guard.inspect_tool_call(request)
    assert decision.allowed
    assert decision.sanitized_arguments is not None
    assert "alice@example.com" not in str(decision.sanitized_arguments)
    assert "[REDACTED:EMAIL]" in decision.sanitized_arguments["query"]
