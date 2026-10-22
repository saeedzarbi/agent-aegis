from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ThreatLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCallRequest(BaseModel):
    """Normalized tool invocation an agent wants to execute."""

    session_id: str
    tenant_id: str = "default"
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_message: str = ""
    agent_reasoning: str = ""


class ThreatSignal(BaseModel):
    rule_id: str
    level: ThreatLevel
    message: str
    evidence: str = ""


class GuardVerdict(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


class GuardDecision(BaseModel):
    verdict: GuardVerdict
    signals: list[ThreatSignal] = Field(default_factory=list)
    sanitized_arguments: dict[str, Any] | None = None
    sanitized_user_text: str | None = None
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def allowed(self) -> bool:
        return self.verdict == GuardVerdict.ALLOW


class AuditEventType(StrEnum):
    USER_INPUT = "user_input"
    TOOL_REQUEST = "tool_request"
    TOOL_DECISION = "tool_decision"
    TOOL_RESULT = "tool_result"


class AuditRecord(BaseModel):
    event_type: AuditEventType
    session_id: str
    tenant_id: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
