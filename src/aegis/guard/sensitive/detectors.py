"""
Pluggable sensitive-data detectors (pure Python, no I/O).

Register new detector classes in ``DETECTOR_REGISTRY`` for Phase 2+ types.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from re import Pattern

from aegis.core.models import ThreatLevel
from aegis.guard.sensitive.types import SensitiveMatch

_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_TOKEN = re.compile(
    r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9._-]+)",
    re.I,
)


def _luhn_ok(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class SensitiveDataDetector(ABC):
    rule_id: str
    kind: str
    level: ThreatLevel
    placeholder: str

    @abstractmethod
    def find(self, text: str) -> list[SensitiveMatch]:
        ...


class EmailDetector(SensitiveDataDetector):
    rule_id = "sensitive_email"
    kind = "email"
    level = ThreatLevel.MEDIUM
    placeholder = "[REDACTED:EMAIL]"

    def find(self, text: str) -> list[SensitiveMatch]:
        return _matches_from_pattern(text, _EMAIL, self)


class UsSsnDetector(SensitiveDataDetector):
    rule_id = "sensitive_ssn"
    kind = "us_ssn"
    level = ThreatLevel.HIGH
    placeholder = "[REDACTED:SSN]"

    def find(self, text: str) -> list[SensitiveMatch]:
        return _matches_from_pattern(text, _SSN, self)


class PaymentCardDetector(SensitiveDataDetector):
    rule_id = "sensitive_payment_card"
    kind = "payment_card"
    level = ThreatLevel.HIGH
    placeholder = "[REDACTED:PAYMENT_CARD]"

    def find(self, text: str) -> list[SensitiveMatch]:
        out: list[SensitiveMatch] = []
        for m in _CARD_CANDIDATE.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if len(digits) < 13 or len(digits) > 19:
                continue
            if not _luhn_ok(digits):
                continue
            out.append(
                SensitiveMatch(
                    rule_id=self.rule_id,
                    kind=self.kind,
                    level=self.level,
                    start=m.start(),
                    end=m.end(),
                    placeholder=self.placeholder,
                )
            )
        return out


class ApiTokenDetector(SensitiveDataDetector):
    rule_id = "sensitive_api_token"
    kind = "api_token"
    level = ThreatLevel.CRITICAL
    placeholder = "[REDACTED:TOKEN]"

    def find(self, text: str) -> list[SensitiveMatch]:
        return _matches_from_pattern(text, _TOKEN, self)


def _matches_from_pattern(
    text: str,
    pattern: Pattern[str],
    detector: SensitiveDataDetector,
) -> list[SensitiveMatch]:
    return [
        SensitiveMatch(
            rule_id=detector.rule_id,
            kind=detector.kind,
            level=detector.level,
            start=m.start(),
            end=m.end(),
            placeholder=detector.placeholder,
        )
        for m in pattern.finditer(text)
    ]


DETECTOR_REGISTRY: list[SensitiveDataDetector] = [
    EmailDetector(),
    UsSsnDetector(),
    PaymentCardDetector(),
    ApiTokenDetector(),
]
