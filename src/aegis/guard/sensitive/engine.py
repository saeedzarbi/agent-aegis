"""
Sensitive-data scan and mask engine.

See ``docs/sanitization-phase1-problem.md`` for scope and integration contract.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from aegis.core.models import ThreatSignal
from aegis.guard.sensitive.detectors import DETECTOR_REGISTRY
from aegis.guard.sensitive.types import SensitiveMatch, SensitiveScanResult


def scan_text(text: str) -> list[SensitiveMatch]:
    """Run all registered detectors on a single string."""
    matches: list[SensitiveMatch] = []
    for detector in DETECTOR_REGISTRY:
        matches.extend(detector.find(text))
    return _dedupe_matches(matches)


def mask_text(text: str, matches: list[SensitiveMatch]) -> str:
    if not matches:
        return text
    ordered = sorted(matches, key=lambda m: m.start, reverse=True)
    out = text
    for m in ordered:
        out = out[: m.start] + m.placeholder + out[m.end :]
    return out


def scan_and_mask_text(text: str) -> SensitiveScanResult:
    matches = scan_text(text)
    masked = mask_text(text, matches) if matches else None
    return SensitiveScanResult(matches=matches, masked_text=masked)


def scan_structure(value: Any) -> list[SensitiveMatch]:
    """Collect matches from string leaves in dict/list structures."""
    matches: list[SensitiveMatch] = []
    _walk_structure(value, matches)
    return _dedupe_matches(matches)


def mask_structure_from_matches(value: Any) -> Any:
    """Scan and mask all string leaves in a JSON-like structure."""

    def walk(node: Any, path: tuple) -> Any:
        if isinstance(node, str):
            m = scan_text(node)
            return mask_text(node, m) if m else node
        if isinstance(node, dict):
            return {k: walk(v, path + (k,)) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(item, path + (i,)) for i, item in enumerate(node)]
        return node

    return walk(deepcopy(value), ())


def matches_to_signals(text: str, matches: list[SensitiveMatch]) -> list[ThreatSignal]:
    signals: list[ThreatSignal] = []
    for m in matches:
        snippet = text[m.start : m.end]
        evidence = snippet[:32] + ("…" if len(snippet) > 32 else "")
        signals.append(
            ThreatSignal(
                rule_id=m.rule_id,
                level=m.level,
                message=f"Sensitive data detected ({m.kind})",
                evidence=evidence,
            )
        )
    return signals


def _walk_structure(node: Any, acc: list[SensitiveMatch]) -> None:
    if isinstance(node, str):
        acc.extend(scan_text(node))
    elif isinstance(node, dict):
        for v in node.values():
            _walk_structure(v, acc)
    elif isinstance(node, list):
        for item in node:
            _walk_structure(item, acc)


def _dedupe_matches(matches: list[SensitiveMatch]) -> list[SensitiveMatch]:
    if not matches:
        return []
    ordered = sorted(matches, key=lambda m: (m.start, m.end, m.rule_id))
    merged: list[SensitiveMatch] = []
    for m in ordered:
        if merged and m.start < merged[-1].end:
            continue
        merged.append(m)
    return merged

