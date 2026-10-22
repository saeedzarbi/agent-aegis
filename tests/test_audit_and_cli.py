"""Audit chain verification and CLI smoke tests."""

from pathlib import Path

from typer.testing import CliRunner

from aegis.audit.chain import AuditChain
from aegis.cli import app
from aegis.core.models import AuditEventType


def test_audit_verify_empty_log(tmp_path: Path):
    ok, detail = AuditChain(tmp_path / "missing.jsonl").verify()
    assert ok
    assert detail == "empty"


def test_audit_chain_append_and_verify(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(path)
    chain.append(AuditEventType.USER_INPUT, "s1", "default", {"text_len": 3})
    ok, detail = AuditChain(path).verify()
    assert ok
    assert detail == "ok"


def test_cli_scan_command():
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "hello world"])
    assert result.exit_code == 0
    assert "Verdict" in result.stdout


def test_cli_check_tool_command():
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "check-tool",
            "search_docs",
            "--args",
            '{"query": "docs"}',
            "--user",
            "find api",
        ],
    )
    assert result.exit_code == 0
