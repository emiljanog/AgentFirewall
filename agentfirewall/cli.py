"""Hook adapter and developer CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone
from .policy import evaluate


def log_decision(payload, result):
    """Avoid logging commands, file names, prompt text, or credentials."""
    filename = os.environ.get('AGENTFIREWALL_AUDIT_FILE')
    if not filename:
        return
    entry = {
        'time': datetime.now(timezone.utc).isoformat(),
        'tool': str(payload.get('tool_name', 'unknown'))[:64],
        'decision': result.action,
        'rule': result.rule,
        'session_hash': hashlib.sha256(str(payload.get('session_id', '')).encode()).hexdigest()[:12],
    }
    try:
        dest = Path(filename).expanduser()
        dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with dest.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry, separators=(',', ':')) + '\n')
        try:
            dest.chmod(0o600)
        except OSError:
            pass
    except OSError:
        # Audit persistence is not guaranteed: do not claim otherwise.
        print('AgentFirewall warning: unable to write audit log', file=sys.stderr)


def hook():
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError('Hook payload must be an object')
    except (ValueError, json.JSONDecodeError):
        payload = {}
    result = evaluate(payload)
    log_decision(payload, result)
    if result.action in ('ask', 'deny'):
        print(json.dumps({'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': result.action,
            'permissionDecisionReason': f'AgentFirewall [{result.rule}]: {result.reason}',
        }}))
    # pass intentionally emits no allow: Claude Code normal permissions apply.
    return 0


def main():
    p = argparse.ArgumentParser(description='AgentFirewall proof-of-concept policy guard')
    sp = p.add_subparsers(dest='subcommand', required=True)
    sp.add_parser('hook', help='Read Claude Code PreToolUse JSON from stdin')
    chk = sp.add_parser('check', help='Evaluate a simulated hook call')
    chk.add_argument('--tool', default='Bash')
    chk.add_argument('--command', help='Bash command')
    chk.add_argument('--path', help='Read/Write/Edit path')
    chk.add_argument('--cwd', default=os.getcwd())
    args = p.parse_args()
    if args.subcommand == 'hook':
        return hook()
    inputs = {'command': args.command} if args.tool == 'Bash' else {'file_path': args.path}
    result = evaluate({'tool_name': args.tool, 'tool_input': inputs, 'cwd': args.cwd})
    print(json.dumps({'decision': result.action, 'reason': result.reason, 'rule': result.rule}, indent=2))
    return 0

if __name__ == '__main__':
    sys.exit(main())
