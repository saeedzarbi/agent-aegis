from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ToolPolicy(BaseModel):
    name: str
    allowed: bool = True
    max_calls_per_session: int = 50
    blocked_argument_keys: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)


class SensitiveDataPolicy(BaseModel):
    """PII/PCI detection before data reaches external LLMs or APIs."""

    enabled: bool = False
    mode: str = "block"  # block | mask
    scan_user_input: bool = True
    scan_tool_arguments: bool = True


class TenantPolicy(BaseModel):
    tenant_id: str
    allowed_tools: list[str] = Field(default_factory=list)
    deny_tools: list[str] = Field(default_factory=list)
    tools: list[ToolPolicy] = Field(default_factory=list)


class Policy(BaseModel):
    """Declarative guard policy (YAML-friendly)."""

    version: int = 1
    default_tenant: str = "default"
    injection_block_level: str = "medium"
    sensitive_data: SensitiveDataPolicy = Field(default_factory=SensitiveDataPolicy)
    tenants: list[TenantPolicy] = Field(default_factory=list)

    def tenant(self, tenant_id: str) -> TenantPolicy:
        for t in self.tenants:
            if t.tenant_id == tenant_id:
                return t
        return TenantPolicy(tenant_id=tenant_id)

    def tool_allowed(self, tenant_id: str, tool_name: str) -> bool:
        tp = self.tenant(tenant_id)
        if tool_name in tp.deny_tools:
            return False
        if tp.allowed_tools and tool_name not in tp.allowed_tools:
            return False
        for spec in tp.tools:
            if spec.name == tool_name:
                return spec.allowed
        return True

    def tool_spec(self, tenant_id: str, tool_name: str) -> ToolPolicy | None:
        for spec in self.tenant(tenant_id).tools:
            if spec.name == tool_name:
                return spec
        return None

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    @classmethod
    def default_demo(cls) -> Policy:
        return cls.model_validate(
            {
                "version": 1,
                "tenants": [
                    {
                        "tenant_id": "default",
                        "allowed_tools": [
                            "search_docs",
                            "send_email",
                            "query_records",
                            "http_fetch",
                        ],
                        "tools": [
                            {
                                "name": "send_email",
                                "max_calls_per_session": 5,
                                "blocked_argument_keys": ["bcc", "attachments"],
                            },
                            {
                                "name": "http_fetch",
                                "allowed_domains": ["api.github.com", "docs.python.org"],
                            },
                        ],
                    }
                ],
            }
        )
