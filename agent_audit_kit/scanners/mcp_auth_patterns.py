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
    r"\b(createServer|McpServer|createMcpHandler|@tool|mcp\.ServeHTTP|FastMCP|"
    r"Server\.run_streamable_http)\b"
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

# AAK-MCP-015, TypeScript tool-handler arm (CVE-2026-94044). The regex above wants
# the request value as the direct first argument of `open` / `fs.readFile`. The
# commonest form of this bug routes it through `path.join` into a variable first,
# and `fs.writeFile` was not a sink at all, so a full scan of the upstream
# app/api/mcp/route.ts reported nothing. This arm follows a name a tool handler
# destructures (`async ({ filePath }) =>`) through one `path.join` / `path.resolve`
# to an fs read or write, and stays silent when the joined path is checked in
# between. Regex and proximity, not data flow, like the language arms of the
# STDIO command-injection family.
_TS_EXTS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs"})
_TS_HANDLER_PARAMS_RE = re.compile(r"\(\s*\{([^{}()]*)\}\s*(?::[^()=]*)?\)\s*=>")
_TS_JOIN_ARGS = r"\(((?:[^()]|\([^()]*\))*)\)"
_TS_JOIN_ASSIGN_RE = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=\s*path\.(join|resolve)\s*" + _TS_JOIN_ARGS
)
_TS_FS_SINK = (
    r"fs\.(?:promises\.)?(readFile|readFileSync|writeFile|writeFileSync|appendFile|"
    r"appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync)"
)
_TS_INLINE_SINK_RE = re.compile(
    _TS_FS_SINK + r"\s*\(\s*path\.(join|resolve)\s*" + _TS_JOIN_ARGS
)
# One handler body: a sink further away than this is not read as the same flow.
_TS_FLOW_WINDOW = 800


def _ts_handler_params(text: str) -> set[str]:
    """Local names tool handlers destructure: `({ filePath, content: body })`."""
    names: set[str] = set()
    for m in _TS_HANDLER_PARAMS_RE.finditer(text):
        for item in m.group(1).split(","):
            local = item.split("=")[0].split(":")[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                names.add(local)
    return names


def _ts_is_guarded(between: str, var: str) -> bool:
    """A containment check on ``var`` between the join and its sink.

    `startsWith` against a base, `path.relative`, `realpath`, or any `if` naming
    the variable that throws or returns, which is how a helper such as
    `if (!inside(fullPath)) throw` reads. Deliberately generous: a check this
    does not understand silences the arm rather than accusing a guarded handler.
    """
    v = re.escape(var)
    return bool(
        re.search(rf"\b{v}\s*\.\s*startsWith\s*\(", between)
        or re.search(rf"path\.relative\s*\([^)]*\b{v}\b", between)
        or re.search(rf"realpath\w*\s*\(\s*{v}\b", between)
        or re.search(rf"\bif\s*\([^;{{]*\b{v}\b[^;{{]*\)\s*\{{?\s*(?:throw|return)\b", between)
    )


def _ts_tool_path_traversal(text: str) -> list[tuple[int, str]]:
    """``(offset, evidence)`` for each tool argument joined onto a path and read
    or written with no containment check in between."""
    names = _ts_handler_params(text)
    if not names:
        return []
    arg_re = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(names))) + r")\b")
    hits: list[tuple[int, str]] = []
    for m in _TS_JOIN_ASSIGN_RE.finditer(text):
        var, fn, args = m.group(1), m.group(2), m.group(3)
        if not arg_re.search(args) or "basename(" in args:
            continue
        window = text[m.end(): m.end() + _TS_FLOW_WINDOW]
        sink = re.search(_TS_FS_SINK + r"\s*\(\s*" + re.escape(var) + r"\b", window)
        if sink is None or _ts_is_guarded(window[: sink.start()], var):
            continue
        hits.append((m.start(), (
            f"`{var} = path.{fn}({args[:80]})` reaches `fs.{sink.group(1)}` "
            "with no containment check"
        )))
    for m in _TS_INLINE_SINK_RE.finditer(text):
        sink_name, fn, args = m.group(1), m.group(2), m.group(3)
        if arg_re.search(args) and "basename(" not in args:
            hits.append((m.start(), (
                f"`fs.{sink_name}(path.{fn}({args[:80]}))` with no containment check"
            )))
    return hits

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

    if path.suffix.lower() in _TS_EXTS:
        # A line the direct-argument regex above already reported is not repeated.
        reported = {f.line_number for f in findings if f.rule_id == "AAK-MCP-015"}
        for offset, evidence in _ts_tool_path_traversal(text):
            line = text.count("\n", 0, offset) + 1
            if line in reported:
                continue
            reported.add(line)
            findings.append(
                make_finding(
                    "AAK-MCP-015",
                    rel,
                    f"Tool argument joined onto a path: {evidence}",
                    line_number=line,
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
