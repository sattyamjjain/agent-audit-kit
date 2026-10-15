"""AAK-ANTHROPIC-SDK-001 — STDIO sanitization-inheritance check.

Anthropic declined to CVE the MCP STDIO design (see OX Security 2026-04-15).
The upstream SDKs pass configuration to the OS as command execution by
design, so every downstream MCP server that uses the SDKs and exposes a
STDIO transport must add its own argv sanitizer. This scanner fires when:

1. A dependency manifest at the project root declares the upstream SDK
   (Python / TS / Java / Rust), read by `_helpers.declares_mcp_sdk`, the gate
   AAK-MCP-STATELESS-001..004 and AAK-MCP-SAMPLING-001 share.
2. A repo file uses a STDIO-transport API from the SDK.
3. None of the opt-outs are present:
   - `shlex.quote` / `shlex.split` call (Python) or `execFile([...])` (Node).
   - An allow-list function (`ALLOWED_`, `WHITELIST`, `VALID_TOOLS`, ...).
   - A config opts out of STDIO (`transports=['http']` / `stdio_disabled`).
   - `.agent-audit-kit.yml` carries `accepts_stdio_risk: true` with a
     non-empty `justification:` field (documented risk acceptance).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import declares_mcp_sdk, in_skip_dir, make_finding

_STDIO_MARKERS = (
    "StdioServerTransport",
    "StdioClientTransport",
    "StdioTransport",
    "stdio_server",
    "StdioServer",
    "stdio_client",
    "StdioClient",
)

_STDIO_OPT_OUT_RE = re.compile(
    r"""
    (?:
        transports\s*=\s*\[\s*['"](?:http|sse|streamable-http)['"]
      | transport\s*[:=]\s*['"](?:http|sse|streamable-http)['"]
      | stdio_disabled\s*[:=]\s*(?:true|True|1)
    )
    """,
    re.VERBOSE,
)

_SANITIZER_HINTS = (
    re.compile(r"\bshlex\.(?:quote|split)\s*\("),
    # The first argument stops at a later `execFile(` that has an argument of
    # its own, which reads on to the same comma: with `[^,]+` alone a file of
    # `execFile(` and no comma read to the end once per call.
    re.compile(r"\bexecFile\s*\((?:(?!\bexecFile\s*\([^,])[^,])+,\s*\["),
    re.compile(r"\b(ALLOWED_[A-Z_]+|WHITELIST_[A-Z_]+|VALID_(?:TOOLS|COMMANDS))\b"),
    re.compile(r"\bProcessBuilder\s*\(\s*(?:List\.of|Arrays\.asList|\[)"),
    re.compile(r"\bstd::process::Command::new\s*\([^)]+\)\s*\.\s*arg\s*\("),
)

_LANG_EXTS_FOR_STDIO_MARKERS = (".py", ".ts", ".tsx", ".js", ".mjs", ".java", ".kt", ".rs")


def _uses_stdio(project_root: Path) -> list[Path]:
    """Return files that contain a STDIO-transport marker."""
    hits: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _LANG_EXTS_FOR_STDIO_MARKERS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(m in text for m in _STDIO_MARKERS):
            hits.append(path)
    return hits


def _has_sanitizer_or_optout(stdio_files: list[Path]) -> bool:
    # Global sanitizer/opt-out markers reachable anywhere in the repo.
    for path in stdio_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _STDIO_OPT_OUT_RE.search(text):
            return True
        for pat in _SANITIZER_HINTS:
            if pat.search(text):
                return True
    return False


def _accepts_risk(project_root: Path) -> bool:
    cfg = project_root / ".agent-audit-kit.yml"
    if not cfg.is_file():
        return False
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    if data.get("accepts_stdio_risk") is not True:
        return False
    justification = data.get("justification")
    return isinstance(justification, str) and justification.strip() != ""


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    # The gate used to be a copy of its own that took pyproject.toml only as the
    # exact quoted "mcp" and cut a requirements line at its first `=`, so
    # "mcp[cli]>=1.2.0", Poetry's `mcp = "^1.2.0"` and `mcp~=1.2.0` never
    # opened it, and a typical Python server was never checked.
    declared, manifests = declares_mcp_sdk(project_root)
    if not declared:
        return [], scanned
    for m in manifests:
        scanned.add(m)

    stdio_files = _uses_stdio(project_root)
    if not stdio_files:
        return [], scanned

    if _accepts_risk(project_root):
        scanned.add(".agent-audit-kit.yml")
        return [], scanned

    if _has_sanitizer_or_optout(stdio_files):
        return [], scanned

    findings: list[Finding] = []
    for path in stdio_files:
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-ANTHROPIC-SDK-001",
            rel,
            "Upstream MCP SDK is declared and a STDIO transport is "
            "exposed without a sanitizer, opt-out, or documented risk "
            "acceptance.",
        ))
    return findings, scanned
