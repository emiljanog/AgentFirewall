# AgentFirewall 🛡️

**Experimental, local-first policy firewall for AI coding agents.**

AgentFirewall intercepts supported Claude Code tool requests **before execution** via `PreToolUse` hooks and applies simple, deterministic policies. A request can be **denied**, **sent for human approval**, or **passed back to Claude Code's normal permission handling**.

> **Security status: proof of concept (v0.1). Do not rely on this as your only security boundary.** It is not a sandbox, antivirus, comprehensive shell interpreter or independently enforced OS firewall. It does not yet include ML-based threat detection, a dashboard, or production-grade guarantees.

## Why build this?

AI coding agents work with code, shells, files and sensitive credentials. Existing agent guardrails often lack a compact, explainable, local-first decision layer. AgentFirewall aims to make risky operations visible and policy-controlled without uploading your source code to a third-party model.

## What works in v0.1

- Claude Code `PreToolUse` adapter for Bash, Read, Write, Edit and MultiEdit.
- Blocks recognized sensitive paths and obvious destructive commands.
- Requests approval for unknown, network or compound shell commands.
- Blocks direct file access outside the agent's project root (for intercepted file tools).
- Optional JSON Lines audit log of decisions (not raw commands or file paths).
- Dependency-light Python CLI and unit tests.

## Quick start

Requirements: Python 3.10+ and Claude Code (for the actual hook integration).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
agentfirewall check --command 'rm -rf /srv/www'
agentfirewall check --command 'npm test'
agentfirewall check --tool Read --path '../secret.txt' --cwd /tmp/myproject
```

On Windows, activate your virtual environment with `.venv\\Scripts\\activate` instead.

### Enable in Claude Code

1. Install this package in a **trusted Python environment** accessible by your Claude Code hook. Use an absolute Python interpreter path for reliability, rather than relying on your shell's activated virtual environment.
2. Open Claude Code user settings at `~/.claude/settings.json` (recommended for a first test, instead of committing project-level hook settings).
3. Merge the `hooks` property from [`examples/claude-settings.json`](examples/claude-settings.json) into your existing settings. Replace `python3` in the example with the absolute path to the interpreter where AgentFirewall was installed.
4. Restart Claude Code and test with benign and destructive commands on a **throwaway project**.

Example input that Claude Code delivers on stdin:

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "cwd": "/home/user/testproject",
  "tool_input": {"command": "rm -rf /srv/site"}
}
```

Simulate it without an agent:

```bash
printf '%s\n' '{"tool_name":"Bash","cwd":"/tmp/project","tool_input":{"command":"rm -rf /srv/site"}}' | python -m agentfirewall hook
```

Expected response includes `"permissionDecision": "deny"`. Safe commands emit no permission override, preserving Claude Code's usual controls.

## Decision model

| Result | Interpretation |
|---|---|
| `deny` | Block the intercepted call |
| `ask` | Ask the user through Claude Code's permission flow |
| `pass` | Emit no approval; Claude Code's normal permissions apply |

**Important:** Hook coverage depends on the agent's supported events and configuration. Shell parsing here is intentionally shallow; indirect filesystem access, alternate interpreters, shell expansions and spawned subprocesses can evade the heuristic classifier. Bash tools can access files independently of the Read/Write/Edit file checks. Tool hooks alone cannot prevent that. Policy files and hook configuration can be changed by users/processes with write access. Run agents with minimal OS permissions and a sandbox for meaningful isolation. Do not point this at production infrastructure as a security boundary.

### Optional audit log

Set `AGENTFIREWALL_AUDIT_FILE` to an absolute path **outside the agent's writable project**. Audit entries include timestamp, tool name, rule, outcome and a truncated SHA-256 hash of the session id. The audit log is best-effort; the hook does not fail closed if writing fails. Protect the audit file with operating-system permissions.

## Architecture

```text
Claude Code → PreToolUse JSON → AgentFirewall Python adapter
                                    ↓
                              Policy evaluation
                                    ↓
                           deny / ask / pass
                                    ↓
                           Claude Code runtime
```

## Roadmap

- [ ] v0.2: structured per-project policy files, explicit schema and validation
- [ ] v0.3: sandbox execution / OS-enforced filesystem isolation
- [ ] v0.4: Codex adapter and native tests against current agent releases
- [ ] v0.5: protected audit daemon + searchable local dashboard
- [ ] v0.6: optional local LLM-assisted risk explanation (never sole enforcement)
- [ ] v1.0: reproducible integration tests, threat model and independent review

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contributing

Ideas, tests, adapters and threat-model improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). For a vulnerability, do not post exploit details in a public issue; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
