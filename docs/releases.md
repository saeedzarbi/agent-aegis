# Releases

## v0.1.0

**Tag:** `v0.1.0`  
**Python:** 3.11+

First public alpha of the in-process agent guard.

### Included

- `GuardPipeline` with `inspect_user_input()` and `inspect_tool_call()`
- Prompt-injection heuristics and tool-centric threat checks
- YAML policy: tenants, tool allowlists, blocked argument keys, `http_fetch` domain allowlists, per-session rate limits
- Hash-chained JSONL audit (`AuditChain`)
- CLI: `aegis scan`, `aegis check-tool`
- **Phase 1 sensitive data** (optional, default off): email, payment card (Luhn), US SSN-shaped IDs, token-like patterns; mask or block
- Example policy (`policies/demo.yaml`) and `examples/mini_agent.py`
- CI: Ruff + pytest with ≥80% coverage

### Docs

- [project-layout.md](project-layout.md)
- [sanitization-phase1-problem.md](sanitization-phase1-problem.md)
- [threat-model.md](threat-model.md)
- [compliance.md](compliance.md)

### Install

```bash
git clone https://github.com/saeedzarbi/agent-aegis.git
cd agent-aegis
pip install -e ".[dev]"
```

Or pin the `v0.1.0` tag when packaging internally.
