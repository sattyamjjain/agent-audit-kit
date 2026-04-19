"""US state consumer-privacy disclosure detection.

Fires AAK-STATE-PRIVACY-001..003 — state-agnostic checks that surface
missing disclosures an AI agent needs when it processes consumer data
of residents covered by any of the 21+ state comprehensive privacy laws.

The Alabama Personal Data Protection Act (HB 351, signed 2026, effective
May 1 2027) is the most recent trigger and the reason this scanner
exists; the rules are written to cover the whole patchwork (CCPA / CPRA,
VCDPA, CPA, CTDPA, UCPA, Iowa, Florida, Texas, Oregon, Delaware,
Montana, Tennessee, Kentucky, Rhode Island, Minnesota, Maryland, New
Hampshire, New Jersey, Indiana, Alabama) rather than hard-coding
Alabama alone.

References:
- Alabama HB 351: https://alison.legislature.state.al.us/files/pdf/SearchableInstruments/2026RS/HB351-eng.pdf
- IAPP tracker: https://iapp.org/resources/article/us-state-privacy-legislation-tracker
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS


_POLICY_EXTS = {".md", ".html", ".txt"}
_MAX_FILE_BYTES = 512_000

# Signals that a file is a privacy policy / consumer-facing doc at all.
_PRIVACY_DOC_RE = re.compile(
    r"\b(?:privacy\s+(?:policy|notice|statement)|data\s+(?:practices|collection)|personal\s+(?:data|information))\b",
    re.IGNORECASE,
)

# Required elements most state laws converge on:
_OPT_OUT_SALE_RE = re.compile(
    r"\b(?:do\s+not\s+sell|opt[- ]out\s+of\s+(?:sale|sharing)|right\s+to\s+opt[- ]out|personal\s+data\s+sale)\b",
    re.IGNORECASE,
)
_RIGHT_TO_ACCESS_RE = re.compile(
    r"\b(?:right\s+to\s+(?:access|know|portability|deletion)|request\s+your\s+data|data\s+subject\s+request|DSAR)\b",
    re.IGNORECASE,
)
_CONTROLLER_CONTACT_RE = re.compile(
    r"\b(?:data\s+protection\s+officer|privacy\s+officer|controller\s+(?:contact|address)|dpo@|privacy@)\b",
    re.IGNORECASE,
)


def _iter_policy_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _POLICY_EXTS:
            continue
        name = path.name.lower()
        # Only look at files that plausibly ARE a policy doc.
        if not any(hint in name for hint in ("privacy", "policy", "terms", "tos", "legal")):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not _PRIVACY_DOC_RE.search(text):
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    if not _OPT_OUT_SALE_RE.search(text):
        findings.append(
            make_finding(
                "AAK-STATE-PRIVACY-001",
                rel,
                "Privacy doc has no opt-out-of-sale / Do-Not-Sell language — "
                "required under CCPA, CPRA, and most post-2023 state laws incl. Alabama DPPA.",
            )
        )

    if not _RIGHT_TO_ACCESS_RE.search(text):
        findings.append(
            make_finding(
                "AAK-STATE-PRIVACY-002",
                rel,
                "Privacy doc does not describe consumer access / deletion / portability rights.",
            )
        )

    if not _CONTROLLER_CONTACT_RE.search(text):
        findings.append(
            make_finding(
                "AAK-STATE-PRIVACY-003",
                rel,
                "Privacy doc does not expose a data-controller contact (DPO / privacy@ / address).",
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_policy_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
