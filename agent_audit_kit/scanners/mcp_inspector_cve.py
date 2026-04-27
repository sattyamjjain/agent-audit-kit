"""AAK-MCP-INSPECTOR-CVE-2026-23744-001 — vendored MCPJam fork RCE.

CVSS 9.8 in mcp-inspector ≤ 1.4.2. Closes the gap between the
config-only AAK-MCP-INSPECTOR preset entry and forks/vendored copies
that ship the vulnerable code unpatched.

Detection:
1. Path-prefix: `vendor/mcpjam-inspector/**`,
   `node_modules/@mcpjam/inspector/**`, `**/mcpjam-inspector/**`.
2. Call-shape: `inspectorServer.handle(<arg>, <arg>)` regardless of
   import path — catches forks where the vendor moved files but kept
   the call shape.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


# Override SKIP_DIRS for this scanner: detecting vendored copies in
# vendor/ + node_modules/ is the whole point.
_INSPECTOR_SKIP_DIRS = SKIP_DIRS - {"vendor", "node_modules"}

_FORK_PATH_HINTS = (
    "mcpjam-inspector",
    "@mcpjam/inspector",
)
_INSPECTOR_CALL_RE = re.compile(
    r"\binspectorServer\s*\.\s*handle\s*\(",
)
_TARGET_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _INSPECTOR_SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in _TARGET_EXTS:
            continue
        rel = str(path.relative_to(project_root))
        rel_lower = rel.lower()

        path_match = any(hint in rel_lower for hint in _FORK_PATH_HINTS)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        call_m = _INSPECTOR_CALL_RE.search(text)

        if not (path_match or call_m):
            continue
        scanned.add(rel)
        line = (text.count("\n", 0, call_m.start()) + 1) if call_m else 1
        evidence = (
            "Vendored mcpjam-inspector fork — CVE-2026-23744 (CVSS 9.8)."
            if path_match
            else "inspectorServer.handle(...) call shape from MCPJam "
                 "Inspector — CVE-2026-23744 vulnerable code path."
        )
        findings.append(make_finding(
            "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
            rel,
            evidence,
            line_number=line,
        ))
    return findings, scanned
