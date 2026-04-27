"""AAK-MCP-ATLASSIAN-CVE-2026-27825/27826 — Atlassian MCP RCE chain.

CVE-2026-27825 (CVSS 9.1) + CVE-2026-27826 (CVSS 8.2) in
mcp-atlassian: Jira/Confluence field content (description, comment
body, PR title) flows from a tool handler into file I/O or subprocess
without validation. Two paired rules so SARIF carries the
distinguishing CVE id per finding.

Sources:
- https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
- https://nvd.nist.gov/vuln/detail/CVE-2026-27825
- https://nvd.nist.gov/vuln/detail/CVE-2026-27826
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding


_ATLASSIAN_HINT_RE = re.compile(
    r"""
    \b(?:
        mcp[-_]?atlassian
      | atlassian[-_]?mcp
      | jira_client
      | confluence_client
      | from\s+atlassian
      | import\s+atlassian
      | issue\.fields\.\w+
      | confluence\.get_page
      | jira\.get_issue
    )\b
    """,
    re.VERBOSE,
)
_FIELD_SOURCE_RE = re.compile(
    r"""
    (?:
        issue\.fields\.\w+
      | issue\.summary
      | issue\.description
      | comment\.body
      | page\.content
      | story\.description
      | ticket\.description
      | get_field\s*\(
    )
    """,
    re.VERBOSE,
)
_DANGEROUS_SINK_RE = re.compile(
    r"""
    (?:
        subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(
      | os\.system\s*\(
      | os\.popen\s*\(
      | open\s*\([^)]*['"]w
      | shutil\.move\s*\(
      | shutil\.copy\s*\(
      | pathlib\.Path[^)]*\.write_(?:text|bytes)
      | with\s+open\s*\([^)]*['"]w
    )
    """,
    re.VERBOSE,
)


def _check_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pkg_files: list[Path] = list(project_root.glob("requirements*.txt"))
    for name in ("pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock"):
        p = project_root / name
        if p.is_file():
            pkg_files.append(p)
    for path in pkg_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(
            r"""(?:^|\n)\s*(?:["']?)mcp-atlassian(?:["']?)\s*[=<>~!]+\s*['"]?([0-9][\w.\-]*)""",
            text,
        )
        if not m:
            continue
        # GHSA / NVD lists patched line — be conservative: any pin <0.1.99
        # (rule prompt asks for "vulnerable-version" placeholder).
        # Until NVD enrichment publishes, fire on any pin to surface for review.
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-ATLASSIAN-CVE-2026-27825-001",
            rel,
            f"mcp-atlassian pinned at {m.group(1)} — CVE-2026-27825 / "
            "CVE-2026-27826 RCE chain via Jira/Confluence field content. "
            "Verify against patched version once NVD enrichment ships.",
            line_number=find_line_number(text, m.group(0)),
        ))
    return findings


def _check_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _ATLASSIAN_HINT_RE.search(text):
            continue
        if not _FIELD_SOURCE_RE.search(text):
            continue
        if not _DANGEROUS_SINK_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        m = _DANGEROUS_SINK_RE.search(text)
        line = (text.count("\n", 0, m.start()) + 1) if m else None
        # CVE-2026-27826 is the lower-severity (CVSS 8.2) variant; use it
        # for file-write sinks. CVE-2026-27825 (CVSS 9.1) for
        # subprocess/os.system sinks.
        sink_match = m.group(0) if m else ""
        if any(t in sink_match for t in ("subprocess", "os.system", "os.popen")):
            rule_id = "AAK-MCP-ATLASSIAN-CVE-2026-27825-001"
        else:
            rule_id = "AAK-MCP-ATLASSIAN-CVE-2026-27826-001"
        findings.append(make_finding(
            rule_id,
            rel,
            f"mcp-atlassian-shape file: Jira/Confluence field content "
            f"reaches {sink_match!r} without validation.",
            line_number=line,
        ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_pin(project_root, scanned))
    findings.extend(_check_pattern(project_root, scanned))
    return findings, scanned
