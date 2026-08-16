"""MCP sidecar HTTP surface scanner — the "dashboard next to the tools" class.

An MCP server is reached over stdio or an authenticated transport, so its own
surface gets scrutiny. The *sidecar* does not: the same process also binds a
local HTTP dashboard / status API / debug UI, and that listener routinely ships
with no authentication at all, because "it only listens on localhost".

Loopback is not an authorization boundary. Two routes reach it:

  * **DNS rebinding.** A page the operator visits resolves ``evil.example`` to a
    public IP, then re-resolves it to ``127.0.0.1``. The browser keeps sending
    ``Host: evil.example`` and the request lands on the loopback listener. The
    only server-side control that stops this is a **Host-header allow-list**;
    binding to loopback does nothing, because the packet really is arriving on
    loopback.
  * **A co-located SSRF.** Any other service on the box that fetches a
    caller-supplied URL will happily fetch ``http://127.0.0.1:<port>/...``.

August 2026 wave — three advisories in one week, one shape:

  - **GHSA-76pc-mqxp-3rq5** / CVE-2026-55156 (npm ``@ooples/token-optimizer-mcp``
    < 5.1.0, CVSS 3.1 5.3): ``/api/session-summary`` and ``/api/session-events``
    take a caller-supplied path with no auth middleware anywhere on the app.
  - **GHSA-rm43-82j9-r4mj** (PyPI ``atomic-agents-stack`` <= 1.0.0, CVSS 4.0 8.2):
    dashboard path traversal to arbitrary file read — the one untrusted-path site
    in the codebase not routed through the project's own ``_io.safe_resolve_under``.
  - **GHSA-9hgc-g3w5-67cm** / CVE-2026-53708 (PyPI ``mcp-contextforge-gateway``
    < 1.0.3): resolve-then-connect TOCTOU on ``/admin/gateways/test`` — covered by
    ``AAK-SSRF-TOCTOU-001``, not by this module.

AAK already carries four *package-specific* pins of this exact shape — Serena
(CVE-2026-49471), Cline (CVE-2026-59723), claude-code-templates
(CVE-2026-73222), Penpot (CVE-2026-45805). This module detects the **pattern**,
so the next one does not need a pin.

Two rules, two different fixes:

``AAK-MCP-SIDECAR-NOAUTH-001`` (high, mcp-config)
    The process registers MCP tools *and* binds an HTTP listener whose routes
    carry no auth dependency or middleware. Fix: put auth on the routes.

``AAK-MCP-SIDECAR-REBIND-001`` (high, transport-security)
    The listener binds loopback with no Host-header allow-list, so loopback is
    being used as the access control. Fix: add the allow-list. Suppressed when
    the app enforces **request-borne** auth (bearer / API key), which a rebinding
    attacker cannot supply. *Not* suppressed by cookie/session auth, which the
    browser attaches for them — that is the whole point of the attack.

Deferral: repos using the MCP SDK's own ``StreamableHTTP`` transport are owned by
``AAK-DNS-REBIND-001``; this module stands down on those so the two do not
double-report the same listener.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, find_line_number, make_finding

NOAUTH_RULE = "AAK-MCP-SIDECAR-NOAUTH-001"
REBIND_RULE = "AAK-MCP-SIDECAR-REBIND-001"

_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")
_MAX_BYTES = 400_000

# --------------------------------------------------------------------------
# MCP identity — the process really is an MCP server, not just any web app.
# --------------------------------------------------------------------------
_MCP_IDENTITY_RE = re.compile(
    r"""
    (?:
        @\w+\.tool\b                      # @mcp.tool / @server.tool
      | \bFastMCP\s*\(
      | \bMcpServer\s*\(
      | \bmodelcontextprotocol\b          # SDK import path
      | \bmcp\.server\b
      | \bsetRequestHandler\s*\(
      | \bListToolsRequestSchema\b
      | \bCallToolRequestSchema\b
      | \bregister_tool\s*\(
      | ["']tools/(?:list|call)["']
    )
    """,
    re.VERBOSE,
)

# --------------------------------------------------------------------------
# An HTTP listener is actually bound (not merely imported).
# --------------------------------------------------------------------------
_LISTEN_RE = re.compile(
    r"""
    (?:
        \buvicorn\.run\s*\(
      | \bhypercorn\b[\w.]*\.serve\s*\(
      | \bapp\.run\s*\(
      | \bserve_forever\s*\(
      | \brun_app\s*\(                    # aiohttp
      | \bHTTPServer\s*\(
      | \bThreadingHTTPServer\s*\(
      | \.listen\s*\(                     # express / fastify / node http
      | \bcreateServer\s*\(
      | \bBun\.serve\s*\(
      | \bDeno\.serve\s*\(
    )
    """,
    re.VERBOSE,
)

# --------------------------------------------------------------------------
# Route registrations. `_ROUTE_RE` finds them; `_TRIVIAL_ROUTE_RE` filters the
# ones whose existence is not itself a finding.
# --------------------------------------------------------------------------
_ROUTE_RE = re.compile(
    r"""
    (?:
        @\s*\w+\.(?:get|post|put|patch|delete|route|api_route)\s*\(\s*["']([^"']*)["']
      | \b(?:app|router|api|server|fastify)\.(?:get|post|put|patch|delete|use|all)
        \s*\(\s*["']([^"']*)["']
      | \badd_api_route\s*\(\s*["']([^"']*)["']
    )
    """,
    re.VERBOSE,
)
_TRIVIAL_ROUTE_RE = re.compile(
    r"^/?(?:health(?:z|check)?|ping|livez|readyz|metrics|version|favicon\.ico|robots\.txt)/?$",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Auth markers.
#
# `_REQUEST_AUTH_RE` is credential material the *caller* must present and a
# browser will not attach on its own — a bearer token, an API-key header, an
# explicit signature check. These defeat DNS rebinding.
#
# `_AMBIENT_AUTH_RE` is auth the browser attaches automatically once the
# operator has a session. It stops an anonymous curl and does nothing at all
# against rebinding, so it clears the no-auth rule but NOT the rebind rule.
# --------------------------------------------------------------------------
_REQUEST_AUTH_RE = re.compile(
    r"""
    (?:
        \bHTTPBearer\b
      | \bHTTPBasic\b
      | \bAPIKeyHeader\b
      | \bSecurity\s*\(
      | \bDepends\s*\(\s*\w*(?:auth|token|key|user|verify|current)\w*
      | \bAuthorization\b
      | \bBearer\b
      | \bX-API-Key\b
      | \bapi[_-]?key\b
      | \bverify_token\b
      | \brequire[_-]?auth\b
      | \brequireAuth\b
      | \bensure_authenticated\b
      | \bexpress-jwt\b
      | \bjwt\.verify\s*\(
      | \bpassport\.authenticate\s*\(
      | \bhmac\.compare_digest\s*\(
      | \bcompare_digest\s*\(
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)
_AMBIENT_AUTH_RE = re.compile(
    r"""
    (?:
        \bflask_login\b
      | \blogin_required\b
      | \bcurrent_user\b
      | \breq\.session\b
      | \brequest\.session\b
      | \bexpress-session\b
      | \bsession\[["']user
      | \bcookies?\.get\s*\(
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# --------------------------------------------------------------------------
# Bind address + Host-header allow-list.
# --------------------------------------------------------------------------
_LOOPBACK_RE = re.compile(
    r"""["'](?:127\.0\.0\.1|localhost|::1|\[::1\])["']|\bhost\s*=\s*["']127\.0\.0\.1["']""",
    re.IGNORECASE,
)
_HOST_ALLOWLIST_RE = re.compile(
    r"""
    (?:
        \bTrustedHostMiddleware\b
      | \ballowed_hosts\b
      | \ballowedHosts\b
      | \bALLOWED_HOSTS\b
      | \bvalidate_host\b
      | \bcheck_host\b
      | \bverify_host\b
      | \breq\.hostname\b
      | \brequest\.host\b
      | \bheaders\.get\s*\(\s*["']host["']
      | \bheaders\[\s*["']host["']
      | \bcheck_origin\b
      | \bverify_origin\b
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# The MCP SDK's own StreamableHTTP transport — AAK-DNS-REBIND-001 owns those.
_STREAMABLE_HTTP_RE = re.compile(
    r"\bStreamableHTTP\w*|\bstreamable_http\b|\bstreamablehttp_\w+", re.IGNORECASE
)


def _iter_source_files(project_root: Path):
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix not in _SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:  # pragma: no cover - defensive
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            yield path, path.read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover - unreadable file
            continue


def _substantive_routes(text: str) -> list[str]:
    """Route paths that are not health/metrics boilerplate."""
    routes: list[str] = []
    for match in _ROUTE_RE.finditer(text):
        path = next((g for g in match.groups() if g is not None), None)
        if path is None:
            continue
        if _TRIVIAL_ROUTE_RE.match(path.strip()):
            continue
        routes.append(path)
    return routes


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Flag MCP servers that also bind an unauthenticated HTTP sidecar."""
    findings: list[Finding] = []
    evaluated = {NOAUTH_RULE, REBIND_RULE}

    for path, text in _iter_source_files(project_root):
        if not _MCP_IDENTITY_RE.search(text):
            continue
        if not _LISTEN_RE.search(text):
            continue
        if _STREAMABLE_HTTP_RE.search(text):
            # AAK-DNS-REBIND-001 owns the SDK's own transport.
            continue

        routes = _substantive_routes(text)
        if not routes:
            continue

        rel = str(path.relative_to(project_root))
        has_request_auth = bool(_REQUEST_AUTH_RE.search(text))
        has_ambient_auth = bool(_AMBIENT_AUTH_RE.search(text))
        listen_line = find_line_number(text, ".listen(") or find_line_number(text, "run(")

        if not has_request_auth and not has_ambient_auth:
            shown = ", ".join(routes[:3])
            findings.append(
                make_finding(
                    NOAUTH_RULE,
                    rel,
                    (
                        f"MCP server also binds an HTTP listener serving {len(routes)} "
                        f"route(s) ({shown}) with no auth dependency or middleware"
                    ),
                    find_line_number(text, routes[0]) or listen_line,
                )
            )

        # Rebinding: loopback is the control, and no Host allow-list backs it up.
        # Request-borne auth defeats rebinding, so it suppresses. Ambient
        # (cookie/session) auth does not — the browser attaches it for the attacker.
        if (
            _LOOPBACK_RE.search(text)
            and not _HOST_ALLOWLIST_RE.search(text)
            and not has_request_auth
        ):
            note = (
                " (session/cookie auth does not help: the browser attaches it"
                " on the attacker's behalf)"
                if has_ambient_auth
                else ""
            )
            findings.append(
                make_finding(
                    REBIND_RULE,
                    rel,
                    (
                        "HTTP listener binds loopback with no Host-header allow-list; "
                        f"loopback is the only access control on {len(routes)} route(s)"
                        f"{note}"
                    ),
                    listen_line,
                )
            )

    return findings, evaluated
