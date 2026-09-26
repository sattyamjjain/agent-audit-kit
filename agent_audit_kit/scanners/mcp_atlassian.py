"""AAK-MCP-ATLASSIAN-CVE-2026-27825/27826: mcp-atlassian before 0.17.0.

NVD records two advisories, both fixed in mcp-atlassian 0.17.0:

- CVE-2026-27825 (CVSS 9.0, CWE-22 + CWE-73): `confluence_download_attachment`
  writes to a caller-supplied `download_path` with no directory boundary, and the
  caller also controls the content, so a written cron entry runs code.
- CVE-2026-27826 (CVSS 8.2, CWE-918): with no Authorization header, two custom
  HTTP headers make the server send requests to any host.

Two paired rules, so SARIF carries the distinguishing CVE id per finding. The pin
reports a declared version below 0.17.0 under both. The source pattern reports a
related class rather than either CVE's own code path: a Jira/Confluence field
reaching an exec sink (27825-001) or a file-write sink (27826-001) in a file that
uses an Atlassian client. This module also carries a source arm for
CVE-2026-73498, described where it is defined.

Sources:
- https://nvd.nist.gov/vuln/detail/CVE-2026-27825
- https://nvd.nist.gov/vuln/detail/CVE-2026-27826
- https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding
from .supply_chain import _semver3


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


# NVD records both advisories as fixed in mcp-atlassian 0.17.0. Until it
# published that version this pin fired on EVERY declared version "to surface for
# review", so a fully patched install was reported as CRITICAL indefinitely; the
# fixture named `patched-pin` (9.9.9) was asserted to fire.
_FIXED_IN: tuple[int, int, int] = (0, 17, 0)
_PIN_FINDINGS: tuple[tuple[str, str], ...] = (
    ("AAK-MCP-ATLASSIAN-CVE-2026-27825-001",
     "CVE-2026-27825 (confluence_download_attachment writes to an unconfined download_path)"),
    ("AAK-MCP-ATLASSIAN-CVE-2026-27826-001",
     "CVE-2026-27826 (two custom headers without Authorization make the server request any host)"),
)
_PIN_RE = re.compile(
    r"""(?:^|\n)\s*(?:["']?)mcp-atlassian(?:["']?)\s*[=<>~!]+\s*['"]?([0-9][\w.\-]*)"""
)


def _check_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    """A declared mcp-atlassian below 0.17.0: one finding per CVE fixed there.

    Only a version it can read is judged, as before: an unpinned install, a
    lockfile's separate name and version lines, and an unparseable version are
    not reported. The version is compared as declared whatever the operator,
    which is how the central pin table reads a requirement too.
    """
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
        m = _PIN_RE.search(text)
        if not m:
            continue
        version = _semver3(m.group(1))
        if version is None or version >= _FIXED_IN:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        # From the offset of the name, not a text search: the match can open with
        # the preceding newline, which no single line contains.
        line = text.count("\n", 0, m.start() + m.group(0).index("mcp-atlassian")) + 1
        for rule_id, what in _PIN_FINDINGS:
            findings.append(make_finding(
                rule_id,
                rel,
                f"mcp-atlassian pinned at {m.group(1)}, below 0.17.0, which fixes {what}.",
                line_number=line,
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
        # The class, not either CVE's own code path (see the module docstring):
        # an exec sink reports under the CRITICAL 27825 rule, a file-write sink
        # under the HIGH 27826 rule.
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


# --- CVE-2026-73498: confluence_upload_attachment arbitrary file read --------
#
# mcp-atlassian < 0.22.0 hands the client-supplied `file_path` argument of
# `confluence_upload_attachment` straight to `open(file_path, "rb")` inside
# `_upload_attachment_direct()`, skipping `validate_safe_path`. The pin table
# (`mcp_cve_pins_2026_07`) owns the dependency-version path; this catches a
# vendored or reimplemented copy of the same handler, where no pin exists to
# read.

_ATTACHMENT_HANDLER_RE = re.compile(
    r"""
    (?:
        def\s+confluence_upload_attachment\s*\(
      | def\s+_upload_attachment_direct\s*\(
      | ["']confluence_upload_attachment["']
    )
    """,
    re.VERBOSE,
)
# The caller-supplied path opened for binary read — the CVE's exact primitive.
_UNVALIDATED_OPEN_RE = re.compile(
    r"""open\s*\(\s*(?:
        file_path
      | filepath
      | attachment_path
      | path
    )\s*,\s*["']rb["']""",
    re.VERBOSE,
)
_PATH_VALIDATION_RE = re.compile(
    r"validate_safe_path"
    r"|is_safe_path"
    r"|resolve\s*\(\s*\)\s*\.\s*relative_to\s*\("
    r"|os\.path\.commonpath\s*\(",
)

# Prose must not clear a finding: a docstring that *mentions* validate_safe_path
# (a TODO, or a comment explaining the bug) is not a call to it. Strip
# triple-quoted strings and `#` comments before looking for the validation call.
_PY_DOCSTRING_RE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.DOTALL)
_PY_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_py_prose(text: str) -> str:
    return _PY_COMMENT_RE.sub(" ", _PY_DOCSTRING_RE.sub(" ", text))


def _check_attachment_traversal(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        code = _strip_py_prose(text)
        if not _ATTACHMENT_HANDLER_RE.search(code):
            continue
        m = _UNVALIDATED_OPEN_RE.search(code)
        if not m:
            continue
        if _PATH_VALIDATION_RE.search(code):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCP-ATLASSIAN-CVE-2026-73498-001",
            rel,
            (
                f"Confluence attachment-upload handler opens the caller-supplied "
                f"path directly ({m.group(0)!r}) with no validate_safe_path check "
                f"— an authenticated MCP client, or an agent induced by untrusted "
                f"content, reads any file the server process can reach and "
                f"exfiltrates it to Confluence as an attachment, including "
                f"CONFLUENCE_API_TOKEN and other credentials (CVE-2026-73498)."
            ),
            line_number=find_line_number(text, m.group(0)),
        ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_pin(project_root, scanned))
    findings.extend(_check_pattern(project_root, scanned))
    findings.extend(_check_attachment_traversal(project_root, scanned))
    return findings, scanned
