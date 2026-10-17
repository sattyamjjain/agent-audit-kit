"""Claude Code hook RCE scanner (CVE-2025-59536 family).

Fires AAK-HOOK-RCE-001 and -002. Inspects settings.json / settings.local.json /
hook script contents for two shapes around CVE-2025-59536: unquoted
interpolation, and shell=True with a dynamic string.

AAK-HOOK-RCE-003 used to fire here on any command in a settings.local.json, as
"pre-trust execution". Whether a project's hooks run before the trust dialog is
a property of the Claude Code release, not of the hook: CVE-2025-59536 is
Claude Code before 1.0.111 running project code ahead of that dialog. The rule
is now a version pin on `@anthropic-ai/claude-code`, a row in
`mcp_cve_pins_2026_07._PINS`.

References:
- https://nvd.nist.gov/vuln/detail/CVE-2025-59536
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    INTERPOLATION_RE,
    SOURCE_MAX_BYTES,
    find_line_number,
    in_skip_dir,
    loads_json,
    make_finding,
    placed,
    read_text_capped,
)


_HOOK_SETTINGS_NAMES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    "settings.local.json",
)
_HOOK_SCRIPT_EXTS = {".sh", ".bash", ".py", ".js", ".ts", ".mjs"}

# _INTERPOLATION_RE now lives in scanners/_helpers.py as INTERPOLATION_RE so
# hook_rce and ide_task_rce share one definition. Kept as a module alias so the
# existing references below (and any importer) stay valid.
_INTERPOLATION_RE = INTERPOLATION_RE

# The argument scan stops at the next call of the same kinds as well as at `)`.
# With a bare `[^)]*`, every call in a script of repeated `spawn(` rescanned to
# the first `)`, so the time grew with the square of the script: 40,000
# characters took 1.9 seconds, and hook scripts are read whatever their size.
# A call nested in the arguments before `shell=True` reads the rest itself, so
# a script matches exactly when it did; the match then starts at that inner call.
#
# A Node options object may name `shell: true` after other options, so the key
# is read after a `{` or a `,`. It was read only right after the `{`, and
# `spawn(cmd, [], { cwd: dir, shell: true })` passed while `{ shell: true, cwd:
# dir }` fired CRITICAL. The `{` or `,` keeps `myshell: true` out.
_SHELL_CALL = (
    r"(?:subprocess\.(?:run|call|Popen|check_output)|os\.system|exec\s*\(|"
    r"child_process\.exec(?:Sync)?|spawnSync|spawn)\s*\("
)
_SHELL_TRUE_RE = re.compile(
    _SHELL_CALL + r"(?:(?!" + _SHELL_CALL + r")[^)])*(?:shell\s*=\s*True|[{,]\s*shell\s*:\s*true)",
    re.IGNORECASE | re.DOTALL,
)

# A shell-execution sink. In a .py/.js/.ts hook script, an interpolated string
# is only an RCE risk if it actually reaches a shell/exec call — otherwise a
# template literal like a React hook's `` `audit:${event}` `` is just data.
_SHELL_SINK_RE = re.compile(
    r"""(?:subprocess\.\w+|os\.system|os\.popen|commands\.getoutput|"""
    r"""child_process|execSync|spawnSync|\bexeca?\b|\bspawn\s*\(|Deno\.run|"""
    r"""\bsh\s+-c\b|\bbash\s+-c\b|\bos\.exec)""",
    re.IGNORECASE,
)
_SHELL_LANG_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs"}


def _iter_hook_files(project_root: Path) -> Iterable[Path]:
    for rel in _HOOK_SETTINGS_NAMES:
        candidate = project_root / rel
        if candidate.is_file():
            yield candidate
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root):
            continue
        parts_lower = {p.lower() for p in path.parts}
        # Claude Code hooks live under a `.claude/` tree. Requiring `.claude`
        # here avoids misclassifying framework hooks — most importantly React
        # hooks under `src/hooks/` (`use-audit.ts`), whose `` `${event}` ``
        # template literals collided with the "hook" keyword.
        if (
            path.suffix.lower() in _HOOK_SCRIPT_EXTS
            and "hooks" in parts_lower
            and ".claude" in parts_lower
        ):
            yield path


def _load_json(path: Path) -> dict | None:
    try:
        return loads_json(read_text_capped(path, CONFIG_MAX_BYTES, errors="replace"), path)
    except (json.JSONDecodeError, OSError):
        return None


def _walk_hook_commands(data: object) -> Iterable[str]:
    """Every string under a command-like key, in document order. Iterative:
    `json.loads` accepts nesting deeper than Python's recursion limit, and the
    recursive walk this was took the scanner down on one such file."""
    stack: list[object] = [data] if isinstance(data, (dict, list)) else []
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            yield node
            continue
        parts: list[object] = []
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str):
                    if key in {"command", "cmd", "run", "script"}:
                        parts.append(value)
                elif isinstance(value, (dict, list)):
                    parts.append(value)
        elif isinstance(node, list):
            parts.extend(item for item in node if isinstance(item, (dict, list)))
        stack.extend(reversed(parts))


def _check_json_settings(path: Path, project_root: Path) -> list[Finding]:
    data = _load_json(path)
    if data is None:
        return []
    unplaced: list[tuple[Finding, str]] = []
    rel = str(path.relative_to(project_root))
    raw = path.read_text(encoding="utf-8", errors="replace")
    for cmd in _walk_hook_commands(data):
        if _INTERPOLATION_RE.search(cmd):
            unplaced.append((
                make_finding(
                    "AAK-HOOK-RCE-001",
                    rel,
                    f"Hook command interpolates user-controlled variable: {cmd!r}",
                ),
                cmd[:60],
            ))
    # Every reported command's line in one pass over the file, not one search of it per command.
    return placed(raw, unplaced)


def _check_hook_script(path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
    except OSError:
        return findings
    rel = str(path.relative_to(project_root))
    m_shell = _SHELL_TRUE_RE.search(text)
    if m_shell:
        # The line comes from the match offset: a match that runs over several
        # lines (an options object written one key a line) is on no single line,
        # and `find_line_number` gave it none.
        findings.append(
            make_finding(
                "AAK-HOOK-RCE-002",
                rel,
                f"Hook script invokes shell with shell=True / {{shell: true}}: {m_shell.group(0)!r}",
                line_number=text.count("\n", 0, m_shell.start()) + 1,
            )
        )
    m_interp = _INTERPOLATION_RE.search(text)
    # For a script *language* (py/js/ts), an interpolation is only an RCE risk
    # if it can reach a shell/exec sink; otherwise it's ordinary string
    # building (e.g. a template literal in a UI helper). Shell scripts
    # (.sh/.bash) are themselves a shell context, so interpolation alone
    # remains sufficient there.
    is_shell_lang = path.suffix.lower() in _SHELL_LANG_EXTS
    if m_interp and path.suffix.lower() in _HOOK_SCRIPT_EXTS:
        if not is_shell_lang or _SHELL_SINK_RE.search(text):
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
