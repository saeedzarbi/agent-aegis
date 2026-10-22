"""Types for the sensitive-data detection layer."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.core.models import ThreatLevel


@dataclass(frozen=True)
class SensitiveMatch:
    """A single sensitive span detected in text."""

    rule_id: str
    kind: str
    level: ThreatLevel
    start: int
    end: int
    placeholder: str

    @property
    def matched_text(self) -> str:
        return ""  # filled by engine when needed for signals only via slice


@dataclass(frozen=True)
class SensitiveScanResult:
    matches: list[SensitiveMatch]
    masked_text: str | None = None
