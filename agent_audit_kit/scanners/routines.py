"""Claude Code Routines scanner (AAK-ROUTINE-001..003).

Routines (research preview, Apr 14 2026) run scheduled prompts non-
interactively. This scanner looks for:

- `.claude/routines/*.{json,yml,yaml}` files
- Permission surfaces wider than interactive default
- Schedule expressions built from runtime state (cron-injection risk)
- Missing audit-log declarations
"""

from __future__ import annotations

import json
import re
from pathlib import Path

try:  # PyYAML is optional but already in deps
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding


_BROAD_PERMS = (
    "fs:*",
    "shell:exec",
    "network:*",
    "credentials:*",
    "env:*",
    "*:*",
)


def _iter_routine_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    routines_dir = project_root / ".claude" / "routines"
    if routines_dir.is_dir():
        for ext in ("*.json", "*.yml", "*.yaml"):
            out.extend(routines_dir.rglob(ext))
    return out


def _load(path: Path) -> tuple[dict | None, str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, ""
    if path.suffix == ".json":
        try:
            return json.loads(raw), raw
        except json.JSONDecodeError:
            return None, raw
    if yaml is None:
        return None, raw
    try:
        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            return data, raw
    except yaml.YAMLError:
        return None, raw
    return None, raw


def _check_routine(data: dict, raw: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    perms = data.get("permissions") or data.get("tools") or []
    if isinstance(perms, list):
        broad = [p for p in perms if p in _BROAD_PERMS]
        if broad:
            findings.append(
                make_finding(
                    "AAK-ROUTINE-001",
                    rel,
                    f"Routine declares broad permissions: {', '.join(broad)}",
                    line_number=find_line_number(raw, broad[0]),
                )
            )

    schedule = (
        data.get("schedule")
        or data.get("cron")
        or data.get("trigger")
        or ""
    )
    if isinstance(schedule, str) and re.search(r"\$\{|\{\{\s*|%\{", schedule):
        findings.append(
            make_finding(
                "AAK-ROUTINE-002",
                rel,
                f"Routine schedule contains variable interpolation: {schedule!r}",
                line_number=find_line_number(raw, schedule),
            )
        )

    audit_declared = any(
        key in data
        for key in ("audit_log", "audit", "log", "output_log")
    )
    if not audit_declared:
        findings.append(
            make_finding(
                "AAK-ROUTINE-003",
                rel,
                "Routine has no audit_log / output_log declaration",
            )
        )
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_routine_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        data, raw = _load(path)
        if isinstance(data, dict):
            findings.extend(_check_routine(data, raw, rel))
    return findings, scanned
