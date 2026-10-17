"""AAK-ANTHROPIC-SDK-001 — STDIO sanitization-inheritance check.

Anthropic declined to CVE the MCP STDIO design (see OX Security 2026-04-15).
The upstream SDKs pass configuration to the OS as command execution by
design, so every downstream MCP server that uses the SDKs and exposes a
STDIO transport must add its own argv sanitizer. This scanner fires when:

1. A dependency manifest at the project root declares the upstream SDK
   (Python / TS / Java / Rust), read by `_helpers.declares_mcp_sdk`, the gate
   AAK-MCP-STATELESS-001..004 and AAK-MCP-SAMPLING-001 share.
2. A repo file builds a STDIO transport from the SDK (one that only names it is not read).
3. That file carries none of the opt-outs, and the project has not accepted
   the risk:
   - `shlex.quote` / `shlex.split` call (Python) or `execFile([...])` (Node).
   - An allow-list function (`ALLOWED_`, `WHITELIST`, `VALID_TOOLS`, ...).
   - A config opts out of STDIO (`transports=['http']` / `stdio_disabled`).
   - `.agent-audit-kit.yml` carries `accepts_stdio_risk: true` with a
     non-empty `justification:` field (documented risk acceptance, the one
     opt-out that covers the whole project).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import (
    CONFIG_MAX_BYTES,
    SOURCE_MAX_BYTES,
    declares_mcp_sdk,
    in_skip_dir,
    load_yaml,
    make_finding,
    read_text_capped,
)

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

# Building a STDIO transport, as opposed to naming one. A file that only
# imports, re-exports, types or mocks a transport (`export { StdioServerTransport }
# from ...`, `jest.mock('.../stdio.js', ...)`) exposes nothing, and once guards
# counted only for their own file, every such file beside a guarded server was
# reported HIGH. A class or function of the same name is a definition, not a
# use. The names are spelled out, with a bounded tail, because `\w*Transport\w*`
# reads a long identifier once for every `Transport` inside it.
_STDIO_CONSTRUCT_RE = re.compile(
    r"""
    (?P<definition>\b(?:class|def|function|fun|interface|type)\s+)?
    (?:
        \bnew\s+Stdio\w{0,48}\s*\(                         # new StdioServerTransport(  (TS/JS/Java)
      | \bStdio(?:Server|Client)?Transport\w{0,16}\s*\(    # StdioServerTransport(...)  (Python/Kotlin)
      | \bstdio_(?:server|client)\s*\(                      # stdio_server() / stdio_client(params)
      | \bStdio\w{0,48}\s*::\s*new\s*\(                     # StdioTransport::new(       (Rust)
    )
    """,
    re.VERBOSE,
)


def _constructs_stdio(text: str) -> bool:
    return any(not m.group("definition") for m in _STDIO_CONSTRUCT_RE.finditer(text))


def _uses_stdio(project_root: Path) -> list[Path]:
    """Return files that build a STDIO transport."""
    hits: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _LANG_EXTS_FOR_STDIO_MARKERS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        if any(m in text for m in _STDIO_MARKERS) and _constructs_stdio(text):
            hits.append(path)
    return hits


def _has_sanitizer_or_optout(path: Path) -> bool:
    """A sanitizer or STDIO opt-out named in this file.

    This used to pool the evidence of every STDIO file in the project, so one
    name anywhere cleared every STDIO transport, whatever the name guarded: an
    `ALLOWED_ORIGINS` list in `src/cors.ts` silenced an unguarded
    `StdioServerTransport` in `src/server.ts`. A guard now counts for the file
    it is written in. A sanitizer kept in another module is not seen from
    here, so the file that imports it is still reported.
    """
    try:
        text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
    except OSError:
        return False
    if _STDIO_OPT_OUT_RE.search(text):
        return True
    return any(pat.search(text) for pat in _SANITIZER_HINTS)


def _accepts_risk(project_root: Path) -> bool:
    cfg = project_root / ".agent-audit-kit.yml"
    if not cfg.is_file():
        return False
    try:
        data = load_yaml(read_text_capped(cfg, CONFIG_MAX_BYTES, errors="replace"), cfg) or {}
    except (yaml.YAMLError, OSError):
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

    findings: list[Finding] = []
    for path in stdio_files:
        if _has_sanitizer_or_optout(path):
            continue
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
