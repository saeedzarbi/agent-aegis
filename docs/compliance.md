# Compliance notes (Agent Aegis)

This document helps security, risk, and compliance reviewers **evaluate** the library. It is not legal advice and does not certify your deployment for any framework.

## What Agent Aegis does

- Runs **in-process** in your Python agent application.
- Inspects **user text** and **tool call requests** you pass in; returns allow, redact, or block with optional sanitized payloads.
- Enforces **YAML policy** you supply (tool allowlists, argument rules, HTTP domain lists, rate limits, optional sensitive-data mode).
- Writes **append-only, hash-chained JSONL** audit events to a path you configure.
- Uses **no network I/O** in its declared runtime dependencies for guard logic (`pyproject.toml`).

## What Agent Aegis does not do

- Store or classify data across your enterprise (not DLP).
- Authenticate users or services (not IAM).
- Block traffic at the network perimeter (not firewall/WAF).
- Sign a Business Associate Agreement, provide a SOC 2 report, or attest to ISO 27001—**those obligations stay with you and your vendors** (cloud LLM provider, hosting, etc.).

## Data handling

| Data | Typical handling |
|------|------------------|
| User message | Processed in memory for inspection; audit records **length** for `user_input` events, not full text by default |
| Tool arguments | Inspected in memory; audit emphasizes tool name and signals—full argument dumps are not the default design |
| Policy YAML | Loaded from disk/path you choose; version with your app |
| Audit file | Written locally; retention, encryption, and access control are **your** controls |

When `sensitive_data.enabled: true`, detected spans can be masked before your code forwards text to an LLM or args to tools—**only if your integration uses** `sanitized_user_text` and `sanitized_arguments`.

## How to evaluate in your environment

1. **Architecture** — Confirm the agent runs where you expect (VPC, on-prem, etc.) and that only approved endpoints receive model traffic.
2. **Policy review** — Treat `policies/*.yaml` like application config; peer review and environment promotion.
3. **Testing** — Run `pytest` and `aegis scan` / `aegis check-tool` in CI on representative payloads.
4. **Audit** — Define who can read audit files, how long you retain them, and how hash-chain verification fits incident response.
5. **Sensitive data** — Decide mask vs block; document known detector limits in [sanitization-phase1-problem.md](sanitization-phase1-problem.md).
6. **Threat model** — See [threat-model.md](threat-model.md) for scope and non-goals.

## SOC 2, ISO 27001, and regulated industries

Achieving or maintaining **SOC 2**, **ISO 27001**, banking supervisory expectations, or PCI DSS scope reduction is a **program-level** effort: people, processes, vendors, logging, access control, and penetration testing across your stack.

Agent Aegis can support **technical controls** in the agent layer (policy enforcement, audit evidence, optional PII/PCI gating). It does **not** by itself:

- satisfy a specific control ID in your framework mapping,
- replace vendor due diligence on your LLM provider,
- or remove regulated data from systems of record.

Document in your own risk register: what the guard covers, what remains manual, and who owns integration correctness.

## Questions?

Open an issue on [GitHub](https://github.com/saeedzarbi/agent-aegis/issues) or extend these docs in-repo for your internal runbooks.
