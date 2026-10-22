# Project layout

The **Agent Aegis** repository root is the workspace root (`/` of this repo). All first-party code lives here:

```text
.
├── src/aegis/           # Library: core, guard, audit, sensitive-data layer
├── tests/               # Pytest suite
├── policies/            # Example YAML policies
├── examples/            # Integration examples (e.g. mini_agent.py)
├── docs/                # Design notes and phase specs
├── .github/workflows/   # CI
├── pyproject.toml       # Package metadata and tooling
└── README.md
```

## Modules

| Package | Responsibility |
|---------|----------------|
| `aegis.core` | Policy models, request/decision types, session context |
| `aegis.guard` | `GuardPipeline`, injection heuristics |
| `aegis.guard.sensitive` | Phase 1 PII/PCI detection and masking |
| `aegis.audit` | Hash-chained JSONL audit log |
| `aegis.cli` | `aegis` Typer CLI |

Other experiments (handoff tooling, decision scanners, app clones) are intentionally **out of tree**.
