"""MCP tool catalogue built from an upstream response with no cap — CVE-2026-84289.

An aggregator asks each configured MCP server for its tools and assembles one
catalogue. Nothing bounds what an upstream may answer with, so the size of the
allocation is chosen by whoever controls the upstream server, not by the
aggregator. Hermes Agent's ``list_tools`` in ``tools/mcp_tool.py`` is the
disclosed instance: read every tool, keep name, description and full input
schema, return the lot. CWE-400 / CWE-789.

``AAK-MCP-016`` looked like the match and is not. Its text is *"An MCP server
endpoint accepts request bodies without a maximum-size limit"* — the **inbound
request**. This allocation is driven by the **upstream response**, a value that
arrives from a different direction and that no body-size limit touches.
Confirmed by scanning the disclosed shape against the whole engine before
writing this: nothing fired, ``AAK-MCP-016`` included.

The conjunction is deliberately narrow, because "builds a list of tools" on its
own describes every MCP client ever written. What makes it a finding is that the
collection being accumulated came off the wire and nothing bounds it: no slice,
no count check, no per-item size check. Add any one of those and the rule goes
quiet, which is what the benign fixture asserts.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, find_line_number, make_finding

_RULE_ID = "AAK-MCP-TOOLS-LIST-UNBOUNDED-001"

_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# A tool-catalogue site: the MCP listing surface, in either language family.
_TOOLS_LIST_RE = re.compile(
    r"\bdef\s+list_tools\b"
    r"|\basync\s+def\s+list_tools\b"
    r"|\blist_tools\s*\("
    r"|ListToolsRequestSchema"
    r"|['\"]tools/list['\"]"
    r"|\blistTools\s*\(",
)

# The collection came off the wire rather than out of a literal in this file.
_REMOTE_SOURCE_RE = re.compile(
    r"\.json\s*\(\s*\)"
    r"|await\s+\w*(?:client|session|resp|response|http\w*)\w*\s*\."
    r"|\bhttpx\s*\.|\brequests\s*\.\s*(?:get|post)\s*\("
    r"|\bfetch\s*\(|\baxios\s*\.",
    re.IGNORECASE,
)

# Accumulation into a catalogue.
_ACCUMULATE_RE = re.compile(
    r"\.append\s*\(|\.extend\s*\(|\.push\s*\(|\.map\s*\(|\bfor\s+\w+\s+in\b|\.concat\s*\(",
)

# Any bound at all. One of these and the allocation is the caller's choice again.
_BOUND_RE = re.compile(
    r"\[\s*:\s*\d+\s*\]"                       # tools[:200]
    r"|\bslice\s*\(\s*0\s*,"                   # .slice(0, 200)
    r"|\bislice\s*\("
    r"|len\s*\([^)]{0,60}\)\s*[<>]"            # len(tools) > MAX
    r"|\.length\s*[<>]"
    r"|\bMAX_[A-Z_]*\b|\bmax_\w+\b"
    r"|\blimit\b|\bcap\b|\btruncat\w*"
    r"|\bbreak\b",
    re.IGNORECASE,
)


def _strip_comments(text: str, is_py: bool) -> str:
    if is_py:
        return text
    return _TS_LINE_COMMENT_RE.sub(" ", _TS_BLOCK_COMMENT_RE.sub(" ", text))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP tool catalogues assembled from an unbounded upstream response.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        text = _strip_comments(raw, path.suffix == ".py")
        if not (
            _TOOLS_LIST_RE.search(text)
            and _REMOTE_SOURCE_RE.search(text)
            and _ACCUMULATE_RE.search(text)
        ):
            continue
        if _BOUND_RE.search(text):
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "MCP tool catalogue is assembled from an upstream server's response "
                "with no bound on how many tools or how large a schema it may "
                "return, so the size of the allocation is chosen by whoever "
                "controls the upstream rather than by this process "
                "(CVE-2026-84289 class, CWE-400/789). A request-body size limit "
                "does not cover this: the value arrives from the other direction. "
                "Cap the tool count and reject oversized schemas before building "
                "the catalogue."
            ),
            find_line_number(raw, "list_tools") or find_line_number(raw, "tools/list"),
        ))

    return findings, scanned_files
