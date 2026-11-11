# Architecture proposal

## v0.1 scope

Pure Python policy evaluation -> Claude Code hook adapter -> optional best-effort log. The adapter never grants permissions directly; it emits only `deny` and `ask` to the calling agent and remains silent on `pass`.

## Future components

1. **Interceptors**: Claude Code hooks, Codex adapter, MCP gateway and a wrapper for supported shells.
2. **Policy engine**: allow/ask/deny with rules for files, command classes, destinations and tool identity.
3. **Isolation**: OS sandbox, container, read-only mounts, limited network access, secrets injection outside writable workspaces.
4. **Risk advisor**: optional local model to explain policy outcomes and recommend tightening; the LLM is not an authority to bypass a deny.
5. **Dashboard**: audit timeline, project profiles, approval metrics and policy editor.
6. **Tamper-resistant auditing**: separate daemon outside agent privileges, bounded retention and redaction.

## Suggested stack

- Interceptors / engine: Python for prototype, Rust or Go if performance or hardening requires it.
- Desktop or local UI: Next.js + Tailwind, backed by a local API.
- Audit data: SQLite for single-host, PostgreSQL only if a multi-host server becomes necessary.
- Tests: unit tests, integration with agent hooks, attack-simulation test fixtures.

## Design principles

- Deterministic policy decisions first.
- Least privilege at the OS boundary.
- Default to human approval for uncertainty.
- No cloud dependency for core decisioning.
- Never leak secrets into logs.
- Threat model and documented failure modes are part of each release.
