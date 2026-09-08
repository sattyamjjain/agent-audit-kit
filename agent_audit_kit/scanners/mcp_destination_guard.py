"""AAK-MCP-DEST-UNVALIDATED-001 — an MCP destination reaches a fetch unguarded.

Two CVEs, one rule, two arms. Written from the 2026-09-08 NVD re-read of #693 and
#699, which showed the pair are not duplicates but the two ends of the same
defect — and that a detector written for either shape alone misses the other.

**Arm A — asymmetry (CVE-2026-85666, OGX / ex-Llama Stack, HIGH 7.5).** NVD:

    MCP tool definitions accept a `server_url` parameter (along with headers and
    authorization values) that is fetched server-side without destination
    validation; *the existing `validate_url_not_private()` guard used for other
    URL inputs is not applied to `server_url`*.

The guard is present. It is called. It is simply not called on this one input.
That is a *within-file inconsistency*, and it is the same class this scanner
already detects at two other layers: auth middleware on `/mcp` but not its twin
`/mcp_message` (CVE-2026-33032, `AAK-MCP-MIDDLEWARE-*`), and a tool gate checked
in `tools/list` but not `tools/call` (CVE-2026-46519). Asymmetry is a much
stronger signal than absence, because the negative case — a module that guards
every destination — is exactly what it passes.

**Arm B — absence (CVE-2026-86122, Rowboat, MEDIUM 5.0).** NVD: Rowboat "fails to
validate custom MCP server and webhook URLs". No guard exists anywhere, so there
is no correct sibling call to compare against and Arm A can never fire. Arm B is
the floor: a destination read from MCP configuration reaches an outbound fetch
and nothing in the module resolves or range-checks anything.

Deliberately narrow, in three ways, because ten `AAK-SSRF-*` rules already exist
and a loose eleventh would report what they report:

  * the destination must be **configuration-shaped** — `server_url`,
    `webhook_url`, `mcp_server_url` and friends, or a `.get("...url")` lookup —
    not any URL. `AAK-MCP-SSRF-001` already owns caller-supplied *tool arguments*;
    this owns destinations that arrive through MCP config.
  * the file must be MCP-relevant. A generic webhook client is not this bug.
  * guard recognition is imported from `ssrf_toctou` rather than re-listed, so a
    guard the other scanner learns to recognise is one this scanner recognises
    too. Divergent copies of that vocabulary is how one of them goes stale.
"""

from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding
from .ssrf_toctou import _guard_functions, _is_validator_name

RULE_ID = "AAK-MCP-DEST-UNVALIDATED-001"

# Destination names that arrive through MCP server / webhook configuration.
# Bare `url` is deliberately absent: it is the single most common identifier in
# any HTTP code and would turn this into the file-wide matcher #593 removed.
_DEST_TOKENS = (
    "server_url", "serverurl", "mcp_url", "mcp_server_url", "webhook_url",
    "callback_url", "endpoint_url", "upstream_url", "remote_url", "target_url",
    "server_uri", "webhook_uri", "endpoint_uri", "sse_url",
)
# `base_url` was in the list above until the first self-scan, which fired it on
# tests/fixtures/cves/cve-2026-73498-mcp-atlassian/negative/attachments.py -- a
# fixture whose whole job is to be clean. It was right to fire and the rule was
# wrong: `base_url` in an API client is the *service's own* address, configured
# once and not steerable by a caller, which is the opposite of the destination
# this rule is about. Dropped rather than special-cased, because every API client
# in the corpus has one.

_FETCH_CALLEES = frozenset({
    "get", "post", "put", "patch", "delete", "head", "request", "send",
    "urlopen", "fetch", "stream", "open",
})
_FETCH_MODULES = frozenset({
    "requests", "httpx", "aiohttp", "urllib", "session", "client",
    "http", "urlopen", "websockets",
})

_MCP_MARKERS = ("mcp", "modelcontext", "tool_call", "tools/call", "list_tools")


def _is_dest_name(name: str | None) -> bool:
    if not name:
        return False
    low = name.lower().lstrip("_")
    return any(low == t or low.endswith("_" + t) or low.startswith(t) for t in _DEST_TOKENS)


def _callee(node: ast.Call) -> tuple[str | None, str | None]:
    """(attribute name, receiver root) for a call, either may be None.

    The receiver walk descends through `Call` as well as `Attribute`, because the
    idiomatic async client is constructed inline —
    `httpx.AsyncClient().get(url)` — and a walk that stops at the first `Call`
    reports no receiver, which is how the first draft of this scanner missed the
    OGX shape it was written for.
    """
    f = node.func
    if isinstance(f, ast.Name):
        return f.id, None
    if isinstance(f, ast.Attribute):
        root: ast.AST = f.value
        while True:
            if isinstance(root, ast.Attribute):
                root = root.value
            elif isinstance(root, ast.Call):
                root = root.func
            elif isinstance(root, ast.Await):
                root = root.value
            else:
                break
        return f.attr, root.id if isinstance(root, ast.Name) else None
    return None, None


def _is_fetch(node: ast.Call) -> bool:
    attr, root = _callee(node)
    if attr is None:
        return False
    if attr in ("urlopen", "fetch"):
        return True
    if attr not in _FETCH_CALLEES:
        return False
    # `.get(...)` on a dict is not a fetch. Require an HTTP-ish receiver.
    return bool(root and root.lower() in _FETCH_MODULES)


def _dest_names_in(node: ast.AST) -> set[str]:
    """Configuration-shaped destination identifiers reachable in an expression.

    Covers three forms the two CVEs actually use: a bare name (`server_url`), an
    attribute (`cfg.server_url`), and a string-keyed lookup
    (`body["server_url"]`, `cfg.get("webhook_url")`).
    """
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and _is_dest_name(sub.id):
            out.add(sub.id)
        elif isinstance(sub, ast.Attribute) and _is_dest_name(sub.attr):
            out.add(sub.attr)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _is_dest_name(sub.value):
            out.add(sub.value)
    return out


def _guarded_names(tree: ast.AST, guards: set[str]) -> set[str]:
    """Identifiers passed to a guard call anywhere in the module."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        attr, _ = _callee(node)
        if not (_is_validator_name(attr) or (attr in guards)):
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Name):
                    out.add(sub.id)
                elif isinstance(sub, ast.Attribute):
                    out.add(sub.attr)
                elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    out.add(sub.value)
    return out


def _analyze(text: str, rel: str) -> list[Finding]:
    low = text.lower()
    if not any(m in low for m in _MCP_MARKERS):
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    guards = _guard_functions(tree, text)
    guarded = _guarded_names(tree, guards)
    # Does the module guard *anything*? Distinguishes Arm A from Arm B.
    has_any_guard = bool(guarded) or bool(guards)

    findings: list[Finding] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_fetch(node):
            continue
        args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in args:
            dests = _dest_names_in(arg)
            for d in sorted(dests):
                if d in guarded or d in seen:
                    continue
                seen.add(d)
                if has_any_guard:
                    ev = (
                        f"`{d}` reaches an outbound fetch with no destination check, "
                        f"while this module does guard other URL inputs "
                        f"({', '.join(sorted(guarded | guards)[:3])}). A guard applied "
                        f"to some destinations and not all is the CVE-2026-85666 shape."
                    )
                else:
                    ev = (
                        f"`{d}` is taken from MCP configuration and reaches an outbound "
                        f"fetch, and nothing in this module resolves or range-checks a "
                        f"destination. This is the CVE-2026-86122 shape."
                    )
                findings.append(make_finding(RULE_ID, rel, ev, node.lineno))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        hits = _analyze(text, rel)
        if hits:
            findings.extend(hits)
            scanned.add(rel)
    return findings, scanned
