# Threat model — v0.1

## Assets

Source code, user files, SSH keys, API tokens, local and remote environments.

## Adversaries

Untrusted repository content, external instructions in tool output, malicious dependencies and mistakes by an otherwise legitimate agent.

## Security assumptions

- Caller invokes the hook for each covered tool.
- Hook binary / policy are trusted and not altered by the agent.
- Claude Code honors `PreToolUse` decisions.
- The user's OS and account permissions are the ultimate security boundary.

## What is covered

Selected direct tool calls matching simple policy rules.

## What is NOT covered

- Arbitrary tool calls outside registered matchers.
- Shell indirection, aliases, alternate interpreters, subprocesses or nontrivial shell syntax.
- Untrusted code run indirectly by approved commands.
- Native network egress control or prevention of exfiltration.
- Untrusted processes running with the user's own privileges.
- Permission-policy or hook-file tampering.
- Race conditions between check and use.
- Guarantee of complete, durable audit events.

## Risk controls for future releases

OS-enforced sandboxing, read-only policy storage, an out-of-process privileged policy controller, signed audit records, opt-in domain egress restrictions, integration and adversarial tests.
