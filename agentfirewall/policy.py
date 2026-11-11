"""Conservative proof-of-concept policies; not a full shell security parser."""
from dataclasses import dataclass
from pathlib import Path
import os
import re
import shlex

@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    rule: str

SENSITIVE = re.compile(r'(^|[/\\])(?:\.env(?:\.[^/\\]+)?|id_(?:rsa|ed25519|ecdsa)|credentials(?:\.json)?|\.npmrc|\.pypirc|\.aws|\.ssh)(?:$|[/\\])', re.I)
DESTRUCTIVE = re.compile(r'\b(?:rm\s+(?:-[^\s]*[rR][^\s]*\s+|--recursive\s+)|mkfs(?:\.[\w]+)?\b|dd\s+.*\bof=|(?:sudo\s+)?shutdown\b|(?:sudo\s+)?reboot\b)', re.I)
NETWORK = re.compile(r'\b(?:curl|wget|scp|rsync|ssh|nc|netcat|ftp)\b', re.I)
META = re.compile(r'[;&|`]|\$\(|\$\{|\n|\r|[<>]')
SAFE = {('npm', 'test'), ('npm', 'run', 'lint'), ('git', 'status'), ('git', 'diff'), ('git', 'log'), ('pwd',), ('ls',), ('pytest',)}


def path_decision(raw: str, cwd: str, tool: str) -> Decision:
    if not isinstance(raw, str) or not raw.strip():
        return Decision('deny', 'Missing file path', 'invalid_path')
    if SENSITIVE.search(raw.replace('\\', '/')):
        return Decision('deny', 'Sensitive credential/configuration path', 'sensitive_path')
    root = Path(cwd).resolve()
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return Decision('deny', 'File access outside the project root', 'outside_project')
    if SENSITIVE.search(str(resolved).replace('\\', '/')):
        return Decision('deny', 'Sensitive credential/configuration path', 'sensitive_path')
    return Decision('pass', 'No restriction matched; normal agent permissions still apply', 'normal_permissions')


def bash_decision(command: str) -> Decision:
    if not isinstance(command, str) or not command.strip():
        return Decision('deny', 'Missing shell command', 'invalid_command')
    if SENSITIVE.search(command.replace('\\', '/')) or re.search(r'(?<![\w.-])(?:\.env(?:\.[\w.-]+)?|id_(?:rsa|ed25519|ecdsa)|\.npmrc|\.pypirc)(?![\w.-])', command, re.I):
        return Decision('deny', 'Command references likely secrets', 'secrets_in_command')
    if DESTRUCTIVE.search(command):
        return Decision('deny', 'Potentially destructive command', 'destructive_command')
    if META.search(command):
        return Decision('ask', 'Compound shell expression or redirection requires review', 'complex_shell')
    try:
        tokens = shlex.split(command)
    except ValueError:
        return Decision('ask', 'Cannot confidently parse the command', 'parse_uncertain')
    if not tokens:
        return Decision('deny', 'Empty command', 'invalid_command')
    if NETWORK.search(tokens[0]):
        return Decision('ask', 'Network or remote operation requires review', 'network_command')
    if any(tuple(tokens[:len(prefix)]) == prefix for prefix in SAFE):
        return Decision('pass', 'Known low-risk command; normal permissions still apply', 'safe_command')
    return Decision('ask', 'Unrecognized command requires review', 'unknown_command')


def evaluate(payload: dict) -> Decision:
    tool = payload.get('tool_name')
    inputs = payload.get('tool_input')
    cwd = payload.get('cwd')
    if not isinstance(tool, str) or not isinstance(inputs, dict) or not isinstance(cwd, str) or not cwd:
        return Decision('deny', 'Incomplete hook input', 'invalid_input')
    if tool == 'Bash':
        return bash_decision(inputs.get('command'))
    if tool in ('Read', 'Write', 'Edit', 'MultiEdit'):
        return path_decision(inputs.get('file_path'), cwd, tool)
    return Decision('ask', 'Unrecognized tool requires user review', 'unknown_tool')
