"""MCP 2026-07-28 routable-header ↔ body desync scanner — AAK-MCP-ROUTING-DESYNC-001.

The ratified 2026-07-28 spec adds **routable request metadata** headers
(SEP-2243): `Mcp-Method` and `Mcp-Name` let proxies / gateways route and
pre-authorize a JSON-RPC call from the HTTP header without parsing the body.

The security hazard is a **confused-deputy / request-smuggling desync**: a proxy
(or the server) makes a routing or authorization decision from the `Mcp-Method`
/ `Mcp-Name` header, but the authoritative JSON-RPC **body** carries a *different*
`method` / tool `name`. A caller sets `Mcp-Method: tools/list` (allowed by the
gateway) while the body invokes `tools/call` on a privileged tool — the header
gate passes, the body executes. The header MUST be validated to equal the body,
or never trusted for a security decision.

This scanner is deterministic and offline. It flags server/proxy source that:
  1. reads the `Mcp-Method` / `Mcp-Name` routable header, AND
  2. uses that value in a routing / authorization decision (dispatch table, an
     allow/deny check, an `if`/`switch` on it), AND
  3. never cross-checks it against the JSON-RPC body method/name.

A file that reads the header *and* asserts it equals the body method (the correct
guard) does not fire — that is the FP-rate contract.

Python: AST is unnecessary here — the shapes are string/attribute reads of the
header name; regex over source (Python/TS/JS/Rust) is the pattern used by the
sibling 2026-07-28 scanners (`mcp_deprecated_features`, `mcp_stateless_migration`).
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".go", ".java"}
_MAX_FILE_BYTES = 1_000_000

# An MCP server/proxy context — gates the whole scan so we never fire on an
# unrelated web app that happens to have a header named similarly.
_MCP_HINT = re.compile(
    r"modelcontextprotocol|FastMCP|McpServer|@mcp\.|mcp\.server|from\s+mcp\b"
    r"|import\s+mcp\b|jsonrpc|json-rpc|tools/call|tools/list|mcpServers",
    re.IGNORECASE,
)

# (1) The SEP-2243 routable header is READ from a request/headers surface.
_HEADER_READ_RE = re.compile(
    r"""(?ix)
    (?:
        headers?\s*(?:\.\s*get\s*\(|\[)\s*["']mcp-(?:method|name)["']   # headers.get("Mcp-Method") / headers["mcp-name"]
      | \.\s*get\s*\(\s*["']mcp-(?:method|name)["']                     # .get("Mcp-Method")
      | request\.headers\b[^\n]{0,40}mcp-(?:method|name)
      | req\.(?:headers|get)\b[^\n]{0,40}mcp-(?:method|name)
      | HTTP_MCP_(?:METHOD|NAME)                                        # WSGI/Django env form
      | ["']mcp-(?:method|name)["']\s*(?:=>|:)                          # header-map literal key
    )
    """,
)

# (2) That header value drives a routing / authorization decision.
_ROUTING_USE_RE = re.compile(
    r"""(?ix)
    (?:
        \b(?:route|router|dispatch|dispatcher|handler[s]?|resolve|forward)\b
      | \b(?:allow(?:ed)?|deny|denied|authori[sz]e[d]?|permit|acl|allowlist|whitelist|is_allowed)\b
      | \bMcp-?Method\b\s*(?:in|==|===|!=|!==)\b
      | \bif\b[^\n]{0,60}\bmcp[_-]?method\b
      | \bswitch\b[^\n]{0,40}\bmcp[_-]?method\b
      | \bROUTES?\b|\bHANDLERS?\b
    )
    """,
)

# (3) A cross-check that the routable header equals the authoritative body
# method/name — the correct guard. Its presence SUPPRESSES the finding.
_BODY_CROSSCHECK_RE = re.compile(
    r"""(?ix)
    (?:
        (?:body|payload|message|msg|rpc|request|data|params?)\s*(?:\.\s*get\s*\(|\[)\s*["']method["']
      | \.\s*method\b[^\n]{0,40}(?:==|===|!=|!==)[^\n]{0,40}mcp[_-]?method
      | mcp[_-]?method\b[^\n]{0,40}(?:==|===|!=|!==)[^\n]{0,60}(?:body|payload|message|msg|rpc|params?|data)\b
      | \bassert\b[^\n]{0,80}mcp[_-]?method
      | header[_-]?body[_-]?match|method[_-]?matches[_-]?body|validate_?routing
    )
    """,
)


def _iter_source(project_root: Path):
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
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
    if not _MCP_HINT.search(text):
        return []
    m_hdr = _HEADER_READ_RE.search(text)
    if not m_hdr:
        return []
    if not _ROUTING_USE_RE.search(text):
        return []
    if _BODY_CROSSCHECK_RE.search(text):
        return []  # correct guard present — do not fire
    rel = str(path.relative_to(project_root))
    return [
        make_finding(
            "AAK-MCP-ROUTING-DESYNC-001",
            rel,
            "Routes/authorizes on the SEP-2243 `Mcp-Method`/`Mcp-Name` routable "
            "header without cross-checking it against the JSON-RPC body method — "
            "a header/body desync lets a caller pass the gateway gate as one "
            "method while the body invokes another.",
            line_number=find_line_number(text, m_hdr.group(0)),
        )
    ]


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
