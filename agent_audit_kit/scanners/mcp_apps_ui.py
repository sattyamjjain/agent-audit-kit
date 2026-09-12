"""MCP Apps (SEP-1865) UI-rendering scanner — AAK-MCP-APPS-001/002.

The ratified 2026-07-28 spec standardizes **MCP Apps** (SEP-1865): an
MCP server can ship interactive `text/html` **UI resources** (`ui://…`) that the
host renders — typically inside an `<iframe>` — and wires to tools via
`postMessage`. Server-provided UI is untrusted content running next to the user's
agent session, so how the host embeds it is a security boundary.

Two deterministic, offline checks (the exact "without sandbox / sanitization"
split the pack calls for):

  - **AAK-MCP-APPS-001 — iframe without a hardening sandbox.** An MCP-App UI
    iframe rendered with no ``sandbox`` attribute, or with a self-defeating
    ``sandbox="allow-scripts allow-same-origin"`` (which lets the framed document
    script the host origin). Server-controlled HTML then executes in the host
    context. NSA CSI "Constrain and sandbox tool execution".

  - **AAK-MCP-APPS-002 — UI content rendered without sanitization.** Server/tool
    -provided content written to the DOM through a raw-HTML sink
    (``innerHTML`` / ``outerHTML`` / ``insertAdjacentHTML`` / React
    ``dangerouslySetInnerHTML`` / Vue ``v-html``) with no sanitizer (DOMPurify /
    ``sanitize*`` / escape) in the file → DOM XSS. NSA CSI "Filter and monitor
    output pipelines".

Scoped to an MCP-Apps context (`ui://`, `@mcp-ui/*`, `createUIResource`, a
`text/html` UI resource, or an iframe in an MCP server/client) so it does not
fire on ordinary web apps. TS/JS/JSX/TSX/HTML/Vue/Svelte source; regex per the
sibling 2026-07-28 scanners.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_SCAN_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte"}
_MAX_FILE_BYTES = 1_000_000

# MCP-Apps context — required before either check fires.
_MCP_APPS_HINT = re.compile(
    r"""(?ix)
    ui://                                   # the MCP Apps UI-resource scheme
  | @mcp-ui/                                # @mcp-ui/client / @mcp-ui/server
  | \bmcp[_-]?ui\b
  | \bmcpApps?\b | \bMCP\s+App\b
  | createUIResource | UIResource
  | text/html\+skybridge                    # MCP Apps templated-HTML mime
  | (?:modelcontextprotocol|McpServer|FastMCP|@modelcontextprotocol/)
    [\s\S]{0,4000}?(?:<iframe|createElement\(\s*["']iframe["'])
    """,
)

# --- APPS-001: iframe sandbox --------------------------------------------
_IFRAME_TAG_RE = re.compile(r"<iframe\b[^>]*>", re.IGNORECASE)
_IFRAME_CREATE_RE = re.compile(r"""createElement\s*\(\s*["']iframe["']""", re.IGNORECASE)
_SANDBOX_ATTR_RE = re.compile(r"""\bsandbox\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_SANDBOX_SET_RE = re.compile(
    r"""\.sandbox\b|setAttribute\s*\(\s*["']sandbox["']|allow\s*=\s*["'][^"']*sandbox""",
    re.IGNORECASE,
)


def _iframe_unsafe(tag: str) -> bool:
    """An iframe tag is unsafe if it has no sandbox, or a sandbox granting BOTH
    allow-scripts and allow-same-origin (which nullifies the sandbox)."""
    m = _SANDBOX_ATTR_RE.search(tag)
    if not m:
        return True  # no sandbox at all
    val = m.group(1).lower()
    return "allow-scripts" in val and "allow-same-origin" in val


# --- APPS-002: raw-HTML sink without sanitizer ---------------------------
_RAW_HTML_SINK_RE = re.compile(
    r"""(?ix)
    \.innerHTML\s*=
  | \.outerHTML\s*=
  | \.insertAdjacentHTML\s*\(
  | dangerouslySetInnerHTML
  | \bv-html\s*=
  | \{@html\b                                # Svelte {@html ...}
    """,
)
_SANITIZER_RE = re.compile(
    r"(?i)DOMPurify|\bsanitize(?:Html|_html|d)?\b|escapeHtml|escape_html|xss\b|\bpurify\b",
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
    if not _MCP_APPS_HINT.search(text):
        return []
    rel = str(path.relative_to(project_root))
    findings: list[Finding] = []

    # APPS-001: iframe sandbox.
    unsafe_iframe = next((t for t in _IFRAME_TAG_RE.findall(text) if _iframe_unsafe(t)), None)
    if unsafe_iframe is not None:
        findings.append(make_finding(
            "AAK-MCP-APPS-001",
            rel,
            f"MCP Apps UI iframe rendered without a hardening sandbox: {unsafe_iframe[:120]!r} "
            "— add sandbox and do not grant allow-scripts together with allow-same-origin.",
            line_number=find_line_number(text, unsafe_iframe[:60]),
        ))
    elif _IFRAME_CREATE_RE.search(text) and not _SANDBOX_SET_RE.search(text):
        m = _IFRAME_CREATE_RE.search(text)
        findings.append(make_finding(
            "AAK-MCP-APPS-001",
            rel,
            "MCP Apps UI iframe created without setting a `sandbox` attribute — "
            "server-provided HTML executes in the host context.",
            line_number=find_line_number(text, m.group(0)) if m else None,
        ))

    # APPS-002: raw-HTML sink without a sanitizer in the file.
    m_sink = _RAW_HTML_SINK_RE.search(text)
    if m_sink and not _SANITIZER_RE.search(text):
        findings.append(make_finding(
            "AAK-MCP-APPS-002",
            rel,
            f"MCP Apps UI writes content to the DOM via a raw-HTML sink "
            f"({m_sink.group(0).strip()!r}) with no sanitizer — untrusted "
            "server/tool content can inject script (DOM XSS).",
            line_number=find_line_number(text, m_sink.group(0)),
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
