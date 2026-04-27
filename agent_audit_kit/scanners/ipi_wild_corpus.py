"""AAK-IPI-WILD-CORPUS-001 — wild IPI payloads in checked-in templates.

10 payload regexes from the 2026-04-24 Help Net Security + Infosec
Magazine catalogue (`agent_audit_kit/data/ipi_wild_payloads_2026_04.json`).
Refresh with `aak corpus update --ipi`.

Fires when source/config files (.md, .txt, .yml, .yaml, .json, .py
docstrings + string literals) embed any of the corpus regexes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_CORPUS_FILE = _DATA_DIR / "ipi_wild_payloads_2026_04.json"
_TARGET_EXTS = (".md", ".txt", ".yml", ".yaml", ".json", ".py")


def _load_corpus() -> list[dict]:
    if not _CORPUS_FILE.is_file():
        return []
    try:
        data = json.loads(_CORPUS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return list(data.get("payloads") or [])


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    payloads = _load_corpus()
    if not payloads:
        return [], set()
    compiled: list[tuple[dict, re.Pattern[str]]] = []
    for entry in payloads:
        regex = entry.get("regex")
        if not isinstance(regex, str):
            continue
        try:
            compiled.append((entry, re.compile(regex)))
        except re.error:
            continue

    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in _TARGET_EXTS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        already_fired: set[str] = set()
        for entry, pat in compiled:
            pid = entry.get("id", "<unknown>")
            if pid in already_fired:
                continue
            m = pat.search(text)
            if m is None:
                continue
            already_fired.add(pid)
            scanned.add(rel)
            line = text.count("\n", 0, m.start()) + 1
            findings.append(make_finding(
                "AAK-IPI-WILD-CORPUS-001",
                rel,
                f"Wild IPI payload {pid} ({entry.get('label', '?')}) — "
                f"see {entry.get('source_url', '?')}",
                line_number=line,
            ))
    return findings, scanned
