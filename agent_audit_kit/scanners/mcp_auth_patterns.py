"""Scanner for 2026 MCP authentication-bypass patterns.

Fires AAK-MCP-011..020. Walks Python/TS/JS source files that look like MCP
server implementations plus relevant config files, matching against regex
patterns drawn from CVE-2026-33032 (Nginx-UI, CVSS 9.8) and the 30+ MCP
CVEs disclosed in Jan–Feb 2026.

Pattern-based, not taint-based. See `typescript_pattern_scan.py` for the
caveats on what regex detection can and cannot prove.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go"}
_MAX_FILE_BYTES = 512_000

_MCP_SERVER_HINT = re.compile(
    r"\b(createServer|McpServer|@tool|mcp\.ServeHTTP|FastMCP|Server\.run_streamable_http)\b"
)

# AAK-MCP-013: CORS wildcard combined with credentials
_CORS_WILDCARD_RE = re.compile(
    r'Access-Control-Allow-Origin["\'\s:=,]+[\'"]\*[\'"]',
    re.IGNORECASE,
)
_CORS_CREDENTIALS_RE = re.compile(
    r'Access-Control-Allow-Credentials["\'\s:=,]+[\'"]?true',
    re.IGNORECASE,
)

# AAK-MCP-014: auth token in URL query param
_AUTH_IN_QUERY_RE = re.compile(
    r"""[?&](?:access_token|api_key|token|auth|bearer)=|"""
    r"""query_params\.get\(\s*['"](?:access_token|api_key|token|auth|bearer)['"]|"""
    r"""req(?:uest)?\.query\.(?:access_token|api_key|token|auth|bearer)\b""",
    re.IGNORECASE,
)

# AAK-MCP-015: user-controlled path to file open
_RESOURCE_OPEN_RE = re.compile(
    r"""\b(?:open|fs\.(?:readFile|readFileSync)|Path\s*\()\s*\(\s*(?:req|request|params|input|args|tool_input|path|file|user_\w+)\b""",
    re.IGNORECASE,
)

# AAK-MCP-017: plain HTTP (not HTTPS) bind in server config
_PLAIN_HTTP_BIND_RE = re.compile(
    r"""(?:listen|bind|serve)\s*\(\s*['"]?http://[^'"\s]*[0-9.]+""",
    re.IGNORECASE,
)

# AAK-MCP-011/012: MCP handler without auth middleware / empty allowlist
_ALLOWLIST_EMPTY_RE = re.compile(
    r"""\b(?:ip_?allowlist|allowed_?ips|cidr_?allowlist)\s*[:=]\s*(?:\[\s*\]|None|null|"")""",
    re.IGNORECASE,
)

# AAK-MCP-011 Python FastAPI / aiohttp handler without Depends(auth) or similar
_FASTAPI_HANDLER_NO_AUTH_RE = re.compile(
    r"""@app\.(?:get|post|put|patch|delete)\(\s*['"]/mcp[^'"]*['"][^)]*\)\s*(?:async\s+)?def\s+\w+\([^)]*\)\s*(?::|\s*->)""",
    re.IGNORECASE | re.DOTALL,
)

# AAK-MCP-018: no rate limit mention near handler
_RATELIMIT_HINT_RE = re.compile(
    r"\b(?:ratelimit|rate_?limit|throttle|limiter)\b",
    re.IGNORECASE,
)


def _iter_source(project_root: Path) -> list[Path]:
    out: list[Path] = []
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
        out.append(path)
    return out


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    if not _MCP_SERVER_HINT.search(text):
        return findings
    rel = str(path.relative_to(project_root))

    if _CORS_WILDCARD_RE.search(text) and _CORS_CREDENTIALS_RE.search(text):
        findings.append(
            make_finding(
                "AAK-MCP-013",
                rel,
                "Wildcard CORS combined with Access-Control-Allow-Credentials: true",
                line_number=find_line_number(text, "Access-Control-Allow-Origin"),
            )
        )

    if _AUTH_IN_QUERY_RE.search(text):
        m = _AUTH_IN_QUERY_RE.search(text)
        findings.append(
            make_finding(
                "AAK-MCP-014",
                rel,
                f"Auth credential passed via URL query param: {m.group(0)!r}" if m else "query-param auth",
                line_number=find_line_number(text, m.group(0)) if m else None,
            )
        )

    if _RESOURCE_OPEN_RE.search(text):
        m = _RESOURCE_OPEN_RE.search(text)
        findings.append(
            make_finding(
                "AAK-MCP-015",
                rel,
                f"User-controlled path passed to file open: {m.group(0) if m else ''!r}",
                line_number=find_line_number(text, m.group(0)) if m else None,
            )
        )

    if _PLAIN_HTTP_BIND_RE.search(text):
        findings.append(
            make_finding(
                "AAK-MCP-017",
                rel,
                "MCP server binds to plain HTTP (no TLS)",
                line_number=find_line_number(text, "http://"),
            )
        )

    if _ALLOWLIST_EMPTY_RE.search(text):
        findings.append(
            make_finding(
                "AAK-MCP-012",
                rel,
                "IP allowlist defaulted to empty (allow-all)",
                line_number=find_line_number(text, "allowlist"),
            )
        )

    if _FASTAPI_HANDLER_NO_AUTH_RE.search(text):
        snippet = _FASTAPI_HANDLER_NO_AUTH_RE.search(text)
        surrounding = text[max(0, (snippet.start() if snippet else 0) - 200) : (snippet.end() if snippet else 0)] if snippet else ""
        if "Depends(" not in surrounding and "@require_auth" not in surrounding:
            findings.append(
                make_finding(
                    "AAK-MCP-011",
                    rel,
                    "FastAPI /mcp* handler with no auth dependency",
                    line_number=find_line_number(text, "/mcp"),
                )
            )

    if "/mcp" in text and not _RATELIMIT_HINT_RE.search(text):
        findings.append(
            make_finding(
                "AAK-MCP-018",
                rel,
                "MCP handler declared without rate-limit keyword anywhere in file",
                line_number=find_line_number(text, "/mcp"),
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
