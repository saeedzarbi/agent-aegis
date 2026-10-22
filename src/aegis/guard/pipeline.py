from __future__ import annotations

from urllib.parse import urlparse

from aegis.audit.chain import AuditChain
from aegis.core.context import SessionContext
from aegis.core.models import (
    AuditEventType,
    GuardDecision,
    GuardVerdict,
    ThreatLevel,
    ThreatSignal,
    ToolCallRequest,
)
from aegis.core.policy import Policy
from aegis.guard.sensitive.engine import (
    mask_structure_from_matches,
    mask_text,
    matches_to_signals,
    scan_structure,
    scan_text,
)
from aegis.guard.threats import scan_tool_arguments, scan_user_text

_LEVEL_ORDER = {
    ThreatLevel.NONE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.CRITICAL: 4,
}


class GuardPipeline:
    """Evaluate user input and tool calls before execution."""

    def __init__(
        self,
        policy: Policy,
        audit: AuditChain | None = None,
        session_context: SessionContext | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit or AuditChain()
        self.sessions = session_context or SessionContext()
        self._block_from = _LEVEL_ORDER[ThreatLevel(policy.injection_block_level)]

    def inspect_user_input(self, session_id: str, tenant_id: str, text: str) -> GuardDecision:
        signals = scan_user_text(text)
        sanitized_user_text: str | None = None
        signals, sanitized_user_text = self._apply_sensitive_user_input(text, signals)
        verdict = self._verdict_from_signals(signals)
        decision = GuardDecision(
            verdict=verdict,
            signals=signals,
            sanitized_user_text=sanitized_user_text,
        )
        self.audit.append(
            AuditEventType.USER_INPUT,
            session_id,
            tenant_id,
            {
                "text_len": len(text),
                "verdict": verdict,
                "signals": [s.model_dump() for s in signals],
            },
        )
        return decision

    def inspect_tool_call(self, request: ToolCallRequest) -> GuardDecision:
        signals: list[ThreatSignal] = []
        signals.extend(scan_user_text(request.user_message))
        signals.extend(scan_tool_arguments(request))

        if not self.policy.tool_allowed(request.tenant_id, request.tool_name):
            signals.append(
                ThreatSignal(
                    rule_id="tool_not_allowed",
                    level=ThreatLevel.HIGH,
                    message=f"Tool `{request.tool_name}` is not allowed for tenant",
                )
            )

        spec = self.policy.tool_spec(request.tenant_id, request.tool_name)
        sanitized = dict(request.arguments)
        signals, sanitized = self._apply_sensitive_tool_arguments(sanitized, signals)
        if spec:
            for key in spec.blocked_argument_keys:
                if key in sanitized:
                    signals.append(
                        ThreatSignal(
                            rule_id="blocked_arg_key",
                            level=ThreatLevel.MEDIUM,
                            message=f"Argument `{key}` is blocked for tool `{request.tool_name}`",
                        )
                    )
                    sanitized.pop(key, None)

            if request.tool_name == "http_fetch" and spec.allowed_domains:
                url = str(sanitized.get("url", ""))
                host = urlparse(url).hostname or ""
                if host and host not in spec.allowed_domains:
                    signals.append(
                        ThreatSignal(
                            rule_id="domain_not_allowed",
                            level=ThreatLevel.HIGH,
                            message=f"Domain `{host}` not in allowlist",
                            evidence=url[:120],
                        )
                    )

            count = self.sessions.record_tool_call(request)
            if count > spec.max_calls_per_session:
                signals.append(
                    ThreatSignal(
                        rule_id="tool_rate_limit",
                        level=ThreatLevel.HIGH,
                        message=f"Tool `{request.tool_name}` exceeded session limit",
                    )
                )

        verdict = self._verdict_from_signals(signals)
        sanitized_args = sanitized if verdict in (GuardVerdict.ALLOW, GuardVerdict.REDACT) else None

        decision = GuardDecision(
            verdict=verdict,
            signals=signals,
            sanitized_arguments=sanitized_args,
        )
        self.audit.append(
            AuditEventType.TOOL_DECISION,
            request.session_id,
            request.tenant_id,
            {
                "tool": request.tool_name,
                "verdict": verdict,
                "decision_id": decision.decision_id,
                "signals": [s.model_dump() for s in signals],
            },
        )
        return decision

    def _verdict_from_signals(self, signals: list[ThreatSignal]) -> GuardVerdict:
        if not signals:
            return GuardVerdict.ALLOW
        high_or_above = [
            s for s in signals if _LEVEL_ORDER[s.level] >= _LEVEL_ORDER[ThreatLevel.HIGH]
        ]
        if any(s.rule_id == "blocked_arg_key" for s in signals) and not high_or_above:
            return GuardVerdict.REDACT
        max_level = max(_LEVEL_ORDER[s.level] for s in signals)
        if max_level >= _LEVEL_ORDER[ThreatLevel.CRITICAL]:
            return GuardVerdict.BLOCK
        if max_level >= self._block_from:
            return GuardVerdict.BLOCK
        return GuardVerdict.ALLOW

    def _apply_sensitive_user_input(
        self,
        text: str,
        signals: list,
    ) -> tuple[list, str | None]:
        cfg = self.policy.sensitive_data
        if not cfg.enabled or not cfg.scan_user_input:
            return signals, None
        matches = scan_text(text)
        if not matches:
            return signals, None
        if cfg.mode == "mask":
            from aegis.core.models import ThreatLevel, ThreatSignal

            signals.append(
                ThreatSignal(
                    rule_id="sensitive_masked",
                    level=ThreatLevel.LOW,
                    message="Sensitive values masked in user text",
                )
            )
            return signals, mask_text(text, matches)
        signals.extend(matches_to_signals(text, matches))
        return signals, None

    def _apply_sensitive_tool_arguments(
        self,
        arguments: dict,
        signals: list,
    ) -> tuple[list, dict]:
        cfg = self.policy.sensitive_data
        if not cfg.enabled or not cfg.scan_tool_arguments:
            return signals, arguments
        matches = scan_structure(arguments)
        if not matches:
            return signals, arguments
        if cfg.mode == "mask":
            from aegis.core.models import ThreatLevel, ThreatSignal

            signals.append(
                ThreatSignal(
                    rule_id="sensitive_masked",
                    level=ThreatLevel.LOW,
                    message="Sensitive values masked in tool arguments",
                )
            )
            return signals, mask_structure_from_matches(arguments)
        signals.extend(_signals_from_structure(arguments))
        return signals, arguments


def _signals_from_structure(node) -> list[ThreatSignal]:
    out: list[ThreatSignal] = []
    if isinstance(node, str):
        ms = scan_text(node)
        out.extend(matches_to_signals(node, ms))
    elif isinstance(node, dict):
        for v in node.values():
            out.extend(_signals_from_structure(v))
    elif isinstance(node, list):
        for item in node:
            out.extend(_signals_from_structure(item))
    return out
