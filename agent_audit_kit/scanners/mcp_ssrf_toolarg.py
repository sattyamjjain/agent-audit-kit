"""MCP tool-argument URL → outbound-fetch SSRF scanner — CVE-2026-14748.

Flags an **MCP tool handler** that passes an **attacker-controllable URL
argument** (a parameter named ``url`` / ``endpoint`` / ``target`` / ``uri`` /
``link`` / ``href`` / ``webhook`` / ``callback``, or a ``*_url`` variant) into an
**outbound HTTP fetch** (``requests`` / ``httpx`` / ``urllib`` / ``aiohttp``)
**without** allow-listing the host or scheme first. An attacker who invokes the
tool controls the destination, so the server fetches internal endpoints, cloud
metadata, or loopback services on the attacker's behalf — the classic
server-side request forgery shape (CWE-918).

Anchor: **CVE-2026-14748** (CVSS 6.3, CWE-918) — NVD verbatim: "A flaw has been
found in AIAnytime Awesome-MCP-Server … the file mcp-wiki/src/mcp_wiki/server.py
of the component mcp-wiki/wiki-summary. This manipulation of the argument url
causes server-side request forgery. The attack may be initiated remotely. The
exploit has been published." (https://nvd.nist.gov/vuln/detail/CVE-2026-14748).

This complements the generic ``AAK-SSRF-001..005`` text family: those key on
request-object accessors (``args[...]`` / ``req.query`` / ``request.json``) and
miss the canonical CVE-2026-14748 shape, where a bare tool-handler **parameter**
named ``url`` flows straight into ``requests.get(url)``. This rule closes that
gap with a stdlib ``ast`` taint path (parameter → fetch sink) — the same taint
mechanism the repo already uses (see ``mcp_auth_pathtraversal``); no new engine.

Detection (Python, ``ast``):
  1. **Context** — the file references an MCP server / tool (``@mcp.tool`` /
     ``FastMCP`` / ``McpServer`` / ``mcp.tool`` / ``@tool`` / ``createTool``).
  2. **Source** — a handler parameter whose name looks like a URL argument
     (``url``, ``endpoint``, ``target``, ``uri``, ``link``, ``href``,
     ``webhook``, ``callback``, or a ``*_url`` variant).
  3. **Sink** — that tainted value (directly or via a simple assignment) reaches
     an outbound fetch: ``requests.<verb>`` / ``httpx.<verb>`` /
     ``urllib.request.urlopen`` / ``urllib.request.Request`` / ``aiohttp`` or a
     ``session``/``client``-style HTTP call.
  4. **Suppressed** when the handler validates the host/scheme first: an
     allow-list (``ALLOWED_HOSTS`` / ``allowlist`` / ``allowed_hosts``), a
     ``urlparse`` + scheme/netloc check, ``ipaddress`` private-range rejection,
     a ``startswith("https")`` scheme pin, or a named SSRF guard helper.

TS / JS / Rust servers use a comment-stripped regex fallback: a ``url``/
``endpoint``/``target`` value passed to ``fetch`` / ``axios`` / ``got`` /
``reqwest`` with no allow-list guard.

FP guards: a host/scheme-validated flow, a constant URL, and non-MCP code PASS.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-SSRF-001"

# The file must look like an MCP server / tool at all.
_MCP_HINT_RE = re.compile(
    r"@mcp\.tool|mcp\.tool|FastMCP|McpServer|modelcontextprotocol|@tool\b"
    r"|createTool|\bmcp_wiki\b|from\s+mcp\b|import\s+mcp\b|mcp\.server"
    r"|@\w+\.tool\b|\.tool\s*\(|\.registerTool\b",
    re.IGNORECASE,
)

# URL-argument source names (parameters + variables): url, endpoint, target,
# uri, link, href, webhook, callback, and `*_url` / `*_endpoint` variants.
_URL_ARG_RE = re.compile(
    r"^(?:[a-z0-9]+_)?(?:url|uri|endpoint|target|link|href|webhook|callback)s?$",
    re.IGNORECASE,
)

# Host / scheme allow-list or SSRF-guard markers that clear the finding.
_GUARD_RE = re.compile(
    r"ALLOW(?:ED)?_HOSTS?|allowed_hosts|allow_?list|url_allow_list|urlparse"
    r"|is_private|ip_address|ip_network|scheme\s*(?:not\s+)?in|netloc\s*(?:not\s+)?in"
    r"|hostname\s*(?:not\s+)?in|startswith\s*\(\s*['\"]https|validate_url|ssrf"
    r"|is_safe_url|check_url|deny",
    re.IGNORECASE,
)

# Outbound-fetch callees (full dotted).
_FETCH_FULL = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch",
    "httpx.head", "httpx.request", "httpx.stream",
    "urllib.request.urlopen", "urllib.request.Request", "urlopen",
    "aiohttp.request",
}
# HTTP verbs used as attribute calls on a client/session receiver.
_FETCH_ATTRS = {"get", "post", "put", "delete", "patch", "head", "request",
                "urlopen", "stream", "fetch"}
# Receiver names that mark an attribute call as an HTTP fetch (avoids `d.get()`).
_CLIENT_RECV_RE = re.compile(
    r"(?:^|[._])(?:client|session|http|https|requests|httpx|aiohttp|conn|urllib)"
    r"[a-z0-9_]*$",
    re.IGNORECASE,
)

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_RUST_SUFFIXES = (".rs",)


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _expr_uses(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(x, ast.Name) and x.id in names for x in ast.walk(node))


def _collect_tainted(fn: ast.AST, seed: set[str]) -> set[str]:
    """Names bound (directly or transitively) to a URL-argument source."""
    tainted = set(seed)
    assigns = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign))]
    for _ in range(6):
        changed = False
        for node in assigns:
            value = getattr(node, "value", None)
            if value is None:
                continue
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        targets.append(t.id)
            elif isinstance(node.target, ast.Name):
                targets.append(node.target.id)
            if targets and _expr_uses(value, tainted):
                for name in targets:
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted


def _is_fetch_sink(call: ast.Call, tainted: set[str]) -> bool:
    """True if this Call is an outbound fetch whose argument is tainted."""
    full = _attr_chain(call.func)
    is_fetch = full in _FETCH_FULL
    if not is_fetch and isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if attr in _FETCH_ATTRS:
            recv = _attr_chain(call.func.value)
            if recv and _CLIENT_RECV_RE.search(recv):
                is_fetch = True
    if not is_fetch and isinstance(call.func, ast.Name) and call.func.id in {"urlopen"}:
        is_fetch = True
    if not is_fetch:
        return False
    # The tainted URL must actually be passed as an argument (positional or kw).
    args: list[ast.AST] = list(call.args)
    args.extend(kw.value for kw in call.keywords if kw.value is not None)
    return any(_expr_uses(a, tainted) for a in args)


def _scan_python(text: str) -> int | None:
    if not _MCP_HINT_RE.search(text):
        return None
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        seed = {
            a.arg
            for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs
            if _URL_ARG_RE.search(a.arg)
        }
        if not seed:
            continue
        tainted = _collect_tainted(fn, seed)

        fn_src = ""
        try:
            fn_src = ast.unparse(fn)
        except Exception:
            pass
        if _GUARD_RE.search(fn_src):
            continue

        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and _is_fetch_sink(node, tainted):
                return node.lineno
    return None


# ---------------------------------------------------------------------------
# TS / JS / Rust (comment-stripped regex fallback)
# ---------------------------------------------------------------------------

_TS_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE = re.compile(r"//[^\n]*")


def _strip_comments(text: str) -> str:
    text = _TS_BLOCK.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return _TS_LINE.sub("", text)


# A URL-ish argument passed to a fetch/axios/got/reqwest call.
_FETCH_ARG_RE = re.compile(
    r"(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got(?:\.(?:get|post))?"
    r"|http\.get|https\.get|reqwest::(?:get|Client)|client\.(?:get|post|request))"
    r"\s*\(\s*"
    r"[^)\n]{0,40}?"
    r"\b(?:[a-z0-9]+[._])?(?:url|uri|endpoint|target|link|href|webhook|callback)s?\b",
    re.IGNORECASE,
)


def _scan_regex(text: str) -> int | None:
    if not _MCP_HINT_RE.search(text):
        return None
    text = _strip_comments(text)
    if _GUARD_RE.search(text):
        return None
    m = _FETCH_ARG_RE.search(text)
    if not m:
        return None
    return text.count("\n", 0, m.start()) + 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP tool-argument URL SSRF (CVE-2026-14748).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        suf = path.suffix
        if suf not in _PY_SUFFIXES + _TS_SUFFIXES + _RUST_SUFFIXES:
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
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        line = _scan_python(text) if suf in _PY_SUFFIXES else _scan_regex(text)
        if line is None:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "An MCP tool handler passes an attacker-controllable URL argument "
                "into an outbound HTTP fetch with no host/scheme allow-list — a "
                "caller-supplied URL reaches internal/loopback/metadata endpoints "
                "server-side (CVE-2026-14748, CWE-918)."
            ),
            line,
        ))

    return findings, scanned_files
