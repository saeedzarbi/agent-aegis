from __future__ import annotations

from collections import defaultdict

from aegis.core.models import ToolCallRequest


class SessionContext:
    """Per-session counters and isolation metadata."""

    def __init__(self) -> None:
        self._tool_counts: dict[tuple[str, str, str], int] = defaultdict(int)

    def record_tool_call(self, request: ToolCallRequest) -> int:
        key = (request.tenant_id, request.session_id, request.tool_name)
        self._tool_counts[key] += 1
        return self._tool_counts[key]

    def tool_call_count(self, request: ToolCallRequest) -> int:
        key = (request.tenant_id, request.session_id, request.tool_name)
        return self._tool_counts[key]
