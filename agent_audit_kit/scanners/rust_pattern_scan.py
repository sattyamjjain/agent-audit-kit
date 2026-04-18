"""Rust dangerous-sink pattern scanner.

This is a **regex pattern scan**, not a real taint analyzer. It looks for
dangerous sinks (std::process::Command with format!, std::fs::write with
interpolated paths, unsafe blocks, etc.) in Rust files that mention MCP
or tool. It does NOT model flow from user-controlled sources.

The module used to be named `rust_scan.py` and documented as "Rust taint
analysis". That overstated what the scanner does; a true Rust taint
tracer would use `syn` or tree-sitter-rust to walk the AST and model
reachability. That may ship later in a separate module.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

# ---- Patterns that indicate an MCP / tool implementation in Rust ----
_MCP_TOOL_RE = re.compile(
    r"\b(mcp|tool)\b",
    re.IGNORECASE,
)

# ---- Dangerous sink patterns mapped to AAK-TAINT rules ----
#
# Each entry: (compiled regex, rule_id, description). A positive finding
# means "a dangerous sink appears in an MCP/tool Rust file", NOT "user
# input reaches this sink".

_DANGEROUS_SINKS: list[tuple[re.Pattern[str], str, str]] = [
    # AAK-TAINT-001: std::process::Command with format! (shell injection via string interpolation)
    (
        re.compile(
            r"Command\s*::\s*new\s*\(\s*(?:&\s*)?format!\s*\(",
        ),
        "AAK-TAINT-001",
        "std::process::Command with format! string (shell injection risk)",
    ),
    # Also catch .arg(format!(...)) patterns
    (
        re.compile(
            r"\.arg\s*\(\s*(?:&\s*)?format!\s*\(",
        ),
        "AAK-TAINT-001",
        "Command .arg() with format! string (shell injection risk)",
    ),
    # AAK-TAINT-002: unsafe blocks in tool handler context
    (
        re.compile(
            r"\bunsafe\s*\{",
        ),
        "AAK-TAINT-002",
        "unsafe block detected in MCP tool handler",
    ),
    # AAK-TAINT-005: sql!/query! macros without parameterized queries
    # Detects sql!(format!(...)) or query!(&format!(...)) patterns
    (
        re.compile(
            r"\b(?:sql|query|query_as)!\s*\(\s*(?:&\s*)?format!\s*\(",
        ),
        "AAK-TAINT-005",
        "SQL macro with format! string (SQL injection risk)",
    ),
    # Also detect string concatenation in sql!/query! macros
    (
        re.compile(
            r"\b(?:sql|query|query_as)!\s*\(\s*(?:&\s*)?\w+\s*\+",
        ),
        "AAK-TAINT-005",
        "SQL macro with string concatenation (SQL injection risk)",
    ),
]


def _is_mcp_tool_file(source: str) -> bool:
    """Return True if the file contains MCP or tool patterns."""
    return bool(_MCP_TOOL_RE.search(source))


def _scan_file(
    source: str,
    rel_path: str,
) -> list[Finding]:
    """Scan a single Rust file for dangerous sink patterns.

    Only files that contain MCP/tool patterns are scanned.

    Args:
        source: The raw source text of the file.
        rel_path: The relative file path for reporting.

    Returns:
        A list of findings for dangerous patterns found in the file.
    """
    if not _is_mcp_tool_file(source):
        return []

    findings: list[Finding] = []
    lines = source.splitlines()

    for line_no, line in enumerate(lines, 1):
        # Skip comment-only lines
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        for pattern, rule_id, description in _DANGEROUS_SINKS:
            if pattern.search(line):
                findings.append(make_finding(
                    rule_id,
                    rel_path,
                    f"{description} (line {line_no}): {line.strip()[:120]}",
                    line_no,
                ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan Rust (.rs) files for taint flows in MCP tool implementations.

    Uses regex-based pattern matching (not AST) to detect dangerous sinks
    in files that contain MCP or tool patterns.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for rs_path in project_root.rglob("*.rs"):
        # Skip excluded directories
        try:
            rel_parts = rs_path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not rs_path.is_file():
            continue

        # Skip large files (> 1 MB)
        try:
            if rs_path.stat().st_size > 1_000_000:
                continue
            source = rs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(rs_path.relative_to(project_root))
        scanned_files.add(rel_path)

        findings.extend(_scan_file(source, rel_path))

    return findings, scanned_files
