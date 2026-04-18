"""TypeScript / JavaScript dangerous-sink pattern scanner.

This is a **regex pattern scan**, not a real taint analyzer. It looks for
dangerous sinks (eval, child_process.exec, fs.writeFile, SQL template
literals, etc.) in files that appear to implement an MCP server. It does
NOT track flow from user-controlled sources to those sinks.

The module used to be named `typescript_scan.py` and documented as
"TypeScript taint analysis". That overstated what the scanner does; a
real taint tracer would walk the TypeScript AST (via tree-sitter or the
`tsc` compiler API) and model source/sink reachability. A true AST-based
analyzer may ship in a later release in a separate module.

For the Python taint analyzer — which IS AST-based — see
`scanners/taint_analysis.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

# ---- Patterns that indicate an MCP server implementation ----
_MCP_SERVER_RE = re.compile(
    r"\b(createServer|McpServer|@tool)\b",
    re.IGNORECASE,
)

# ---- Dangerous sink patterns mapped to AAK-TAINT rules ----
#
# Each entry: (compiled regex, rule_id, description)
# These are pattern matches on file contents. A positive finding means
# "a dangerous sink was called somewhere in a file that looks like an MCP
# server" — NOT "user input reaches this sink".

_DANGEROUS_SINKS: list[tuple[re.Pattern[str], str, str]] = [
    # AAK-TAINT-002: eval() usage
    (
        re.compile(r"\beval\s*\("),
        "AAK-TAINT-002",
        "eval() call detected in MCP server file",
    ),
    # AAK-TAINT-001: child_process.exec() / execSync() usage
    (
        re.compile(
            r"\b(?:child_process\s*\.\s*)?(?:exec|execSync|spawn|spawnSync)\s*\(",
        ),
        "AAK-TAINT-001",
        "child_process exec/spawn call detected in MCP server file",
    ),
    # AAK-TAINT-003: fs.writeFileSync / fs.writeFile with potential user input
    (
        re.compile(
            r"\b(?:fs\s*\.\s*)?(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\(",
        ),
        "AAK-TAINT-003",
        "fs write call detected in MCP server file",
    ),
]


def _is_mcp_server_file(source: str) -> bool:
    """Return True if the file contains MCP server patterns."""
    return bool(_MCP_SERVER_RE.search(source))


def _scan_file(
    source: str,
    rel_path: str,
) -> list[Finding]:
    """Scan a single TypeScript file for dangerous sink patterns.

    Only files that contain MCP server patterns are scanned.

    Args:
        source: The raw source text of the file.
        rel_path: The relative file path for reporting.

    Returns:
        A list of findings for dangerous patterns found in the file.
    """
    if not _is_mcp_server_file(source):
        return []

    findings: list[Finding] = []
    lines = source.splitlines()

    for line_no, line in enumerate(lines, 1):
        # Skip comment-only lines
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*"):
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
    """Scan TypeScript/TSX files for taint flows in MCP server implementations.

    Uses regex-based pattern matching (not AST) to detect dangerous sinks
    in files that contain MCP server patterns (createServer, McpServer, @tool).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for suffix in ("*.ts", "*.tsx"):
        for ts_path in project_root.rglob(suffix):
            # Skip excluded directories
            try:
                rel_parts = ts_path.relative_to(project_root).parts
            except ValueError:
                continue
            if any(part in SKIP_DIRS for part in rel_parts):
                continue
            if not ts_path.is_file():
                continue

            # Skip large files (> 1 MB)
            try:
                if ts_path.stat().st_size > 1_000_000:
                    continue
                source = ts_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel_path = str(ts_path.relative_to(project_root))
            scanned_files.add(rel_path)

            findings.extend(_scan_file(source, rel_path))

    return findings, scanned_files
