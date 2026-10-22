from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from aegis.audit.chain import AuditChain
from aegis.core.models import ToolCallRequest
from aegis.core.policy import Policy
from aegis.guard.pipeline import GuardPipeline

app = typer.Typer(
    name="aegis",
    help="Agent Aegis — policy guardrails for tool-calling AI agents",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    message: str = typer.Argument(..., help="User message to inspect"),
    policy: Path = typer.Option(None, "--policy", "-p", help="Policy YAML path"),
) -> None:
    """Scan user input for injection patterns."""
    pol = Policy.from_yaml(policy) if policy else Policy.default_demo()
    guard = GuardPipeline(pol)
    decision = guard.inspect_user_input("cli", pol.default_tenant, message)
    _print_decision(decision)


@app.command("check-tool")
def check_tool(
    tool: str = typer.Argument(..., help="Tool name"),
    args: str = typer.Option("{}", "--args", help="JSON object of tool arguments"),
    user_message: str = typer.Option("", "--user", help="Originating user message"),
    policy: Path = typer.Option(None, "--policy", "-p"),
) -> None:
    """Evaluate a tool call before the agent executes it."""
    import json

    pol = Policy.from_yaml(policy) if policy else Policy.default_demo()
    guard = GuardPipeline(pol)
    request = ToolCallRequest(
        session_id="cli",
        tenant_id=pol.default_tenant,
        tool_name=tool,
        arguments=json.loads(args),
        user_message=user_message,
    )
    decision = guard.inspect_tool_call(request)
    _print_decision(decision)


@app.command()
def verify_audit(
    log_file: Path = typer.Argument(..., help="JSONL audit log path"),
) -> None:
    """Verify hash chain integrity of an audit log."""
    ok, detail = AuditChain(path=log_file).verify()
    if ok:
        console.print(f"[green]Audit chain valid[/green] ({detail})")
        raise typer.Exit(0)
    console.print(f"[red]Audit chain invalid[/red]: {detail}")
    raise typer.Exit(1)


def _print_decision(decision) -> None:
    color = {"allow": "green", "block": "red", "redact": "yellow"}.get(decision.verdict, "white")
    console.print(f"Verdict: [{color}]{decision.verdict}[/]")
    if decision.sanitized_user_text is not None:
        console.print(f"Sanitized user text: {decision.sanitized_user_text}")
    if decision.sanitized_arguments is not None:
        console.print(f"Sanitized args: {decision.sanitized_arguments}")
    if not decision.signals:
        return
    table = Table("Rule", "Level", "Message")
    for s in decision.signals:
        table.add_row(s.rule_id, s.level, s.message)
    console.print(table)


if __name__ == "__main__":
    app()
