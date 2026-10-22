# Threat model (Agent Aegis)

Plain-language view of what we protect, where trust breaks, and what this library does **not** try to fix.

## Assets

| Asset | Why it matters |
|-------|----------------|
| **User and session content** | Chat text, pasted IDs, account numbers—often regulated |
| **Tool arguments** | URLs, email recipients, query params—where side effects happen |
| **Policy configuration** | YAML that defines allowed tools, domains, limits, sensitive-data mode |
| **Audit log** | Hash-chained JSONL of guard decisions; evidence for investigations |
| **Downstream systems** | Email gateways, HTTP APIs, internal apps invoked by agent tools |

## Trust boundaries

```text
[ End user ] ──► [ Your agent app + Aegis (same process) ] ──► [ Your LLM ]
                              │
                              ▼
                    [ Your tool implementations ]
                              │
                              ▼
                    [ External / internal services ]
```

- **Inside the boundary you control:** agent code, Aegis, policy files, audit file path, wiring to model and tools.
- **Outside:** hosted LLMs, third-party SaaS, the open internet, your IdP, network firewalls, enterprise DLP.

Aegis runs **before** you hand data to an external model or execute a tool. It does not sit on the network edge.

## Threats and mitigations

| Threat | What could happen | What Aegis does today |
|--------|-------------------|------------------------|
| **Prompt injection** | User text tricks the model into unsafe tool use or policy bypass | Heuristic signals on user input; configurable block levels |
| **Tool smuggling** | Disallowed tool names or dangerous argument keys (e.g. `bcc`) | Tenant tool allowlists; per-tool `blocked_argument_keys`; domain allowlists for `http_fetch` |
| **Secret exfil in args** | API tokens or key-shaped strings in tool payloads | Pattern checks in `threats`; Phase 1 token-like detectors in sensitive layer |
| **PII/PCI leak to LLM** | Card numbers, SSN-shaped data, emails forwarded to cloud models | Optional Phase 1 scan on user input and tool args; **mask** or **block**; default **off** |
| **Runaway automation** | Agent loops or spam via tools | Per-session rate limits on configured tools |
| **Malicious or mistaken policy** | Overly permissive YAML checked into prod | Policy is code—review in PRs, test with `pytest` / CLI; Aegis does not validate business intent |
| **Audit tampering** | Attacker edits log to hide tool abuse | Hash chain on append; does not encrypt or ship logs off-host by itself |

## Explicit non-goals

Agent Aegis is **not**:

- **DLP** — no enterprise content discovery across stores, email gateways, or endpoints
- **IAM / auth** — no user login, RBAC, or service identity; your app must authenticate callers
- **Network firewall / WAF** — no packet inspection or TLS termination
- **Model safety** — no guarantee the LLM won’t hallucinate or ignore instructions after the guard allows a turn
- **Sandbox for tool code** — you still execute tools you write; Aegis only gates the call

Use it as a **deterministic check in the agent loop**, alongside whatever compliance stack you already run.

## Residual risk

- Heuristics miss novel injection phrasing.
- Regex PII detection false-positives and false-negatives are expected; not a substitute for tokenization in source systems.
- If the app ignores `sanitized_user_text` / `sanitized_arguments`, sensitive data can still reach external APIs—that’s an integration bug, not something the library can prevent alone.

## Related docs

- [sanitization-phase1-problem.md](sanitization-phase1-problem.md) — sensitive-data scope
- [compliance.md](compliance.md) — how reviewers can evaluate the library
- [project-layout.md](project-layout.md) — code map
