# Phase 1: Sensitive data detection (problem definition)

## Problem

Agent Aegis today inspects **user text** and **tool arguments** for prompt-injection patterns and a narrow set of **API-token-shaped secrets** in tool args (`guard/threats.py`). It does **not** detect common **PII/PCI** fields (emails, payment card numbers, government identifiers) that must not be sent to **external LLMs or third-party APIs** in regulated environments (banking, critical infrastructure).

Callers integrate their own LLM and HTTP tools **outside** this library. Without an explicit, policy-driven sanitization layer, sensitive payloads can pass the guard while still being forwarded to cloud models or external endpoints.

## Goal (Phase 1)

Add a **modular, pure-Python** sensitive-data layer that:

1. Scans **user input** and **tool argument values** (string leaves in JSON-like structures).
2. Detects a first set of patterns: **email**, **payment card numbers** (with Luhn check), **US SSN-shaped IDs**, and **token-like secrets** (existing patterns).
3. Applies policy **`block`** (fail closed) or **`mask`** (replace matches with typed placeholders) before the caller proceeds.
4. Emits **threat signals** and optional **sanitized payloads** consistent with existing `GuardDecision` / audit behavior.
5. Defaults to **`enabled: false`** so existing deployments behave unchanged until policy opts in.

## Non-goals (Phase 1)

- No external API calls, ML classifiers, or locale-specific national-ID databases.
- No MCP/HTTP sidecar (later phases).
- No encryption at rest for audit logs (documented separately).

## Success criteria

- Baseline tests prove behavior **without** sensitive policy unchanged.
- With `sensitive_data.enabled: true`, representative PII/PCI in input or tool args is **blocked or masked** per policy.
- Detectors are registered in an extensible registry for future types (IBAN, phone, custom regex).

## Integration point

`GuardPipeline.inspect_user_input` and `inspect_tool_call` invoke the sensitive-data engine when policy enables it, after existing heuristics, and attach `sanitized_user_text` / updated `sanitized_arguments` on allow/redact paths.
