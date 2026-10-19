from __future__ import annotations

import re
from re import Pattern

from aegis.core.models import ThreatLevel, ThreatSignal, ToolCallRequest

# Heuristic patterns for instruction override and tool misuse in user text.
_INJECTION_PATTERNS: list[tuple[str, Pattern[str], ThreatLevel, str]] = [
    (
        "ignore_instructions",
        re.compile(
            r"(ignore|disregard|forget)\s+(all\s+)?(previous|prior)(\s+system)?\s+"
            r"(instructions|rules|prompts)",
            re.I,
        ),
        ThreatLevel.HIGH,
        "Attempt to override system instructions",
    ),
    (
        "tool_smuggle",
        re.compile(r"<\s*/?\s*tool[_\s-]?call|function\s*:\s*\w+\s*\(", re.I),
        ThreatLevel.CRITICAL,
        "Embedded tool-call markup in user text",
    ),
    (
        "exfil_secret",
        re.compile(
            r"(dump|print|reveal|send).{0,40}(api[_\s-]?key|secret|password|token|env)",
            re.I,
        ),
        ThreatLevel.CRITICAL,
        "Possible secret exfiltration intent",
    ),
    (
        "role_escape",
        re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.I),
        ThreatLevel.MEDIUM,
        "Role reassignment phrasing",
    ),
]

_SECRET_IN_ARGS = re.compile(
    r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9._-]+)",
    re.I,
)


def scan_user_text(text: str) -> list[ThreatSignal]:
    signals: list[ThreatSignal] = []
    for rule_id, pattern, level, message in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            signals.append(
                ThreatSignal(
                    rule_id=rule_id,
                    level=level,
                    message=message,
                    evidence=match.group(0)[:120],
                )
            )
    return signals


def scan_tool_arguments(request: ToolCallRequest) -> list[ThreatSignal]:
    signals: list[ThreatSignal] = []
    blob = " ".join(str(v) for v in request.arguments.values())
    secret = _SECRET_IN_ARGS.search(blob)
    if secret:
        signals.append(
            ThreatSignal(
                rule_id="secret_in_tool_args",
                level=ThreatLevel.CRITICAL,
                message="Tool arguments contain token-like material",
                evidence=secret.group(0)[:32] + "…",
            )
        )
    return signals
