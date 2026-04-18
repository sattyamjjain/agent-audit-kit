"""Claude Code hook RCE scanner (CVE-2025-59536 family).

Fires AAK-HOOK-RCE-001..003. Inspects settings.json / settings.local.json /
hook script contents for the three shapes that composed CVE-2025-59536:
unquoted interpolation, shell=True with dynamic string, and project-local
hook files that would execute before the trust prompt.

References:
- https://nvd.nist.gov/vuln/detail/CVE-2025-59536
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_HOOK_SETTINGS_NAMES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    "settings.local.json",
)
_HOOK_SCRIPT_EXTS = {".sh", ".bash", ".py", ".js", ".ts", ".mjs"}

_INTERPOLATION_RE = re.compile(
    r"""(?:["']\s*\+\s*|\$\{|%\{|{{\s*|\$\(|`)\s*(?:input|args|event|payload|user|argv|request)""",
    re.IGNORECASE,
)

_SHELL_TRUE_RE = re.compile(
    r"""(?:subprocess\.(?:run|call|Popen|check_output)|os\.system|exec\s*\(|child_process\.exec(?:Sync)?|spawnSync|spawn)\s*\([^)]*(?:shell\s*=\s*True|{\s*shell\s*:\s*true)""",
    re.IGNORECASE | re.DOTALL,
)


def _iter_hook_files(project_root: Path) -> Iterable[Path]:
    for rel in _HOOK_SETTINGS_NAMES:
        candidate = project_root / rel
        if candidate.is_file():
            yield candidate
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in _HOOK_SCRIPT_EXTS and "hooks" in {p.lower() for p in path.parts}:
            yield path


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _walk_hook_commands(data: object) -> Iterable[str]:
    if isinstance(data, dict):
        for key, value in data.items():
            if key in {"command", "cmd", "run", "script"} and isinstance(value, str):
                yield value
            yield from _walk_hook_commands(value)
    elif isinstance(data, list):
        for item in data:
            yield from _walk_hook_commands(item)


def _check_json_settings(path: Path, project_root: Path) -> list[Finding]:
    data = _load_json(path)
    if data is None:
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))
    raw = path.read_text(encoding="utf-8", errors="replace")
    commands = list(_walk_hook_commands(data))
    for cmd in commands:
        if _INTERPOLATION_RE.search(cmd):
            findings.append(
                make_finding(
                    "AAK-HOOK-RCE-001",
                    rel,
                    f"Hook command interpolates user-controlled variable: {cmd!r}",
                    line_number=find_line_number(raw, cmd[:60]),
                )
            )
    if path.name == "settings.local.json" or "settings.local.json" in str(path):
        if commands:
            findings.append(
                make_finding(
                    "AAK-HOOK-RCE-003",
                    rel,
                    "Project-local settings.local.json defines hook commands — pre-trust execution risk",
                    line_number=1,
                )
            )
    return findings


def _check_hook_script(path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    rel = str(path.relative_to(project_root))
    m_shell = _SHELL_TRUE_RE.search(text)
    if m_shell:
        findings.append(
            make_finding(
                "AAK-HOOK-RCE-002",
                rel,
                f"Hook script invokes shell with shell=True / {{shell: true}}: {m_shell.group(0)!r}",
                line_number=find_line_number(text, m_shell.group(0)),
            )
        )
    m_interp = _INTERPOLATION_RE.search(text)
    if m_interp and path.suffix.lower() in _HOOK_SCRIPT_EXTS:
        findings.append(
            make_finding(
                "AAK-HOOK-RCE-001",
                rel,
                f"Hook script interpolates user input into a shell-ish context: {m_interp.group(0)!r}",
                line_number=find_line_number(text, m_interp.group(0)),
            )
        )
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_hook_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        if path.suffix.lower() == ".json":
            findings.extend(_check_json_settings(path, project_root))
        else:
            findings.extend(_check_hook_script(path, project_root))
    return findings, scanned
