"""VS Code IDE task / launch folder-open RCE scanner (AAK-IDE-TASK-001..004).

`.vscode/tasks.json` and `.vscode/launch.json` are agent-adjacent config the
scanner did not read before today: `.vscode/mcp.json` was covered, the task
surface was not. The keyv npm worm (2025) spread by shipping a task with
`runOptions.runOn: folderOpen`, which executes the moment a victim opens the
repository — before any interaction and before the workspace-trust prompt.

Detections:
- AAK-IDE-TASK-001: a task that auto-runs on `folderOpen` (HIGH; CRITICAL when
  the command is a shell, an interpreter, or a network fetch).
- AAK-IDE-TASK-002: a task whose command/args reach a shell — pipe-to-shell, an
  interpreter invoked on a repo-local script path, or a `${...}`/interpolated
  variable spliced into a shell string (reuses the shared INTERPOLATION_RE).
- AAK-IDE-TASK-003: a `launch.json` configuration whose `preLaunchTask` points at
  a task flagged by 001/002 — one finding naming both files.
- AAK-IDE-TASK-004: the file could not be parsed even after stripping JSONC
  comments and trailing commas (LOW, informational — an unparseable config is
  exactly where an auto-run task would hide).

These files are JSONC (VS Code permits comments and trailing commas), so a plain
`json.loads` raises on real-world files; comments and trailing commas are
stripped first, respecting string context so a `//` inside a URL survives.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding, Severity
from agent_audit_kit.rules.builtin import get_rule
from agent_audit_kit.scanners._helpers import (
    INTERPOLATION_RE,
    SKIP_DIRS,
    find_line_number,
)

_VSCODE_DIR = ".vscode"

# A command is a shell / interpreter / network fetch — escalates a folderOpen
# auto-run (AAK-IDE-TASK-001) from HIGH to CRITICAL.
_SHELL_CMD_RE = re.compile(
    r"\b(?:sh|bash|zsh|dash|ksh|fish|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)\b",
    re.IGNORECASE,
)
_INTERPRETER_RE = re.compile(
    r"\b(?:python[23]?|node|deno|bun|ruby|perl|php|osascript|npx|uvx|pipx)\b",
    re.IGNORECASE,
)
_NET_FETCH_RE = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest|invoke-expression|iex)\b",
    re.IGNORECASE,
)

# AAK-IDE-TASK-002 shell-reaching shapes.
_PIPE_TO_SHELL_RE = re.compile(
    r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|fish|pwsh|powershell)\b",
    re.IGNORECASE,
)
# An interpreter invoked on a script path inside the repo, e.g. `python ./x.py`,
# `node scripts/setup.js`, `bash ./install.sh`.
_INTERP_REPO_PATH_RE = re.compile(
    r"\b(?:python[23]?|node|deno|bun|ruby|perl|php|bash|sh|zsh)\b\s+"
    r"\.?[\w./\\-]*[\w-]+\.(?:py|js|cjs|mjs|ts|rb|pl|php|sh|bash|zsh|ps1)\b",
    re.IGNORECASE,
)


def _finding(
    rule_id: str,
    file_path: str,
    evidence: str,
    line_number: int | None = None,
    severity: Severity | None = None,
) -> Finding:
    """Like ``_helpers.make_finding`` but with an optional severity override.

    AAK-IDE-TASK-001 is HIGH by default and escalates to CRITICAL when the
    auto-run command is a shell / interpreter / network fetch, so the finding's
    severity can differ from the rule's registered default.
    """
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        description=rule.description,
        severity=severity or rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_number,
        evidence=evidence,
        remediation=rule.remediation,
        cve_references=rule.cve_references,
        owasp_mcp_references=rule.owasp_mcp_references,
        owasp_agentic_references=rule.owasp_agentic_references,
        adversa_references=rule.adversa_references,
        incident_references=rule.incident_references,
        aicm_references=rule.aicm_references,
    )


def _strip_jsonc(text: str) -> str:
    """Strip `//` and `/* */` comments and trailing commas, respecting strings.

    A naive strip would corrupt `"https://example.com"`; this walks the text and
    only treats `//` / `/*` as comments when not inside a double-quoted string.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    stripped = "".join(out)
    # Trailing commas before a closing } or ].
    stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
    return stripped


def _flatten_strings(value: object) -> list[str]:
    """Flatten a command/args value (string, platform dict, or list) to strings.

    VS Code allows `command` as a string or a platform object
    (`{"windows": ..., "linux": ...}`), and `args` as strings or
    `{"value": ..., "quoting": ...}` objects.
    """
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_flatten_strings(v))
    elif isinstance(value, list):
        for v in value:
            out.extend(_flatten_strings(v))
    return out


def _iter_config_files(project_root: Path, name: str) -> Iterable[Path]:
    for path in project_root.rglob(name):
        if path.parent.name != _VSCODE_DIR:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def _parse(path: Path, rel: str) -> tuple[object | None, Finding | None]:
    """Return (data, None) on success, or (None, parse-failure finding)."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None
    try:
        return json.loads(_strip_jsonc(raw)), None
    except (json.JSONDecodeError, ValueError) as exc:
        return None, _finding(
            "AAK-IDE-TASK-004",
            rel,
            f"could not parse as JSON/JSONC even after stripping comments: {exc}",
            line_number=1,
        )


def _command_is_critical(task: dict, joined: str) -> bool:
    """A folderOpen auto-run is critical if it reaches a shell/interpreter/fetch."""
    if str(task.get("type", "")).lower() == "shell":
        return True
    return bool(
        _SHELL_CMD_RE.search(joined)
        or _INTERPRETER_RE.search(joined)
        or _NET_FETCH_RE.search(joined)
    )


def _scan_tasks(path: Path, rel: str) -> tuple[list[Finding], set[str]]:
    """Scan a tasks.json; return (findings, labels flagged by 001/002)."""
    data, parse_fail = _parse(path, rel)
    if parse_fail is not None:
        return [parse_fail], set()
    if not isinstance(data, dict):
        return [], set()
    raw = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []
    flagged: set[str] = set()
    tasks = data.get("tasks")
    if not isinstance(tasks, list):
        return [], set()
    for task in tasks:
        if not isinstance(task, dict):
            continue
        label = task.get("label")
        label_str = label if isinstance(label, str) else ""
        joined = " ".join(
            _flatten_strings(task.get("command")) + _flatten_strings(task.get("args"))
        ).strip()
        anchor = label_str or joined[:60]
        line = find_line_number(raw, anchor) if anchor else 1

        run_on = ""
        run_options = task.get("runOptions")
        if isinstance(run_options, dict):
            run_on = str(run_options.get("runOn", "")).lower()

        if run_on == "folderopen":
            critical = _command_is_critical(task, joined)
            sev = Severity.CRITICAL if critical else Severity.HIGH
            why = (
                "runs a shell/interpreter/network command"
                if critical
                else "runs on folder open"
            )
            findings.append(
                _finding(
                    "AAK-IDE-TASK-001",
                    rel,
                    f"task {label_str or '(unlabelled)'!r} auto-executes on folderOpen "
                    f"and {why}: {joined!r}",
                    line_number=line,
                    severity=sev,
                )
            )
            if label_str:
                flagged.add(label_str)

        if joined and (
            _PIPE_TO_SHELL_RE.search(joined)
            or _INTERP_REPO_PATH_RE.search(joined)
            or INTERPOLATION_RE.search(joined)
        ):
            findings.append(
                _finding(
                    "AAK-IDE-TASK-002",
                    rel,
                    f"task {label_str or '(unlabelled)'!r} command/args reach a shell: "
                    f"{joined!r}",
                    line_number=line,
                )
            )
            if label_str:
                flagged.add(label_str)

    return findings, flagged


def _scan_launch(
    path: Path, rel: str, tasks_rel: str | None, flagged: set[str]
) -> list[Finding]:
    data, parse_fail = _parse(path, rel)
    if parse_fail is not None:
        return [parse_fail]
    if not isinstance(data, dict):
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    findings: list[Finding] = []
    configs = data.get("configurations")
    if not isinstance(configs, list):
        return []
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        pre = cfg.get("preLaunchTask")
        if isinstance(pre, str) and pre in flagged:
            name = cfg.get("name")
            name_str = name if isinstance(name, str) else "(unnamed)"
            where = f" (flagged in {tasks_rel})" if tasks_rel else ""
            findings.append(
                _finding(
                    "AAK-IDE-TASK-003",
                    rel,
                    f"launch config {name_str!r} preLaunchTask {pre!r} chains to a "
                    f"flagged auto-exec task{where}",
                    line_number=find_line_number(raw, pre) or 1,
                )
            )
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    # Flagged task labels per .vscode dir, so a launch.json's preLaunchTask can be
    # tied back to the tasks.json in the same folder (AAK-IDE-TASK-003).
    flagged_by_dir: dict[Path, tuple[str, set[str]]] = {}

    for tf in _iter_config_files(project_root, "tasks.json"):
        rel = str(tf.relative_to(project_root))
        scanned.add(rel)
        task_findings, labels = _scan_tasks(tf, rel)
        findings.extend(task_findings)
        flagged_by_dir[tf.parent] = (rel, labels)

    for lf in _iter_config_files(project_root, "launch.json"):
        rel = str(lf.relative_to(project_root))
        scanned.add(rel)
        tasks_rel, labels = flagged_by_dir.get(lf.parent, (None, set()))
        findings.extend(_scan_launch(lf, rel, tasks_rel, labels))

    return findings, scanned
