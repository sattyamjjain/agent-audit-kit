"""OAuth 2.1 misconfiguration scanner.

Fires AAK-OAUTH-001..008. MCP spec 2025-11-25 makes OAuth 2.1 mandatory with
PKCE+S256, RFC 8707 Resource Indicators, and RFC 9728 Protected Resource
Metadata; this scanner pattern-matches violations in source code and config
files. AAK-OAUTH-006/007/008 are the 2026-07-28 final auth-profile conformance
checks (`--profile mcp-2026-07-28`).
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".yaml", ".yml", ".toml"}
_MAX_FILE_BYTES = 512_000

_OAUTH_HINT = re.compile(
    r"\b(?:oauth|authorization_endpoint|token_endpoint|client_id|authorize\()",
    re.IGNORECASE,
)

_PKCE_PRESENT_RE = re.compile(
    r"\b(?:code_verifier|pkce)\b|"
    r"code_challenge(?!_method)",  # plain 'code_challenge' but not 'code_challenge_method'
    re.IGNORECASE,
)
_PKCE_PLAIN_RE = re.compile(
    r"code_challenge_method['\"]?\s*[:=]\s*['\"]?plain\b",
    re.IGNORECASE,
)
_WILDCARD_REDIRECT_RE = re.compile(
    r"""redirect_uri(?:s)?['\"]?\s*[:=]\s*['\"]?\[\s*['\"]\*['\"]|"""
    r"""redirect_uri(?:s)?['\"]?\s*[:=]\s*['\"]?(?:\*|https?://\*|http://localhost[:/]?)|"""
    r"""redirect_uri(?:s)?\s*:\s*\[\s*['\"]\*['\"]""",
    re.IGNORECASE,
)
_TOKEN_FORWARD_RE = re.compile(
    r"""(?:["']Authorization["']\s*:\s*(?:request|req|event|input)\.headers\s*\[|"""
    r"""(?:headers|request\.headers)\s*\[\s*['\"]Authorization['\"]\s*\]\s*=\s*(?:request\.|req\.|event\.|input\.))""",
    re.IGNORECASE,
)
_BEARER_ONLY_RE = re.compile(
    r"Bearer\s+['\"]?(?:[a-zA-Z0-9_\-\.]+)['\"]?",
)
_DPOP_HINT_RE = re.compile(r"\b(?:DPoP|dpop)\b|cnf\b", re.IGNORECASE)

# RFC 9207 (MCP 2026-07-28 RC, SEP-2468): the client must validate the `iss`
# authorization-response parameter. Fire when the file handles an authorization
# response (token exchange with grant_type=authorization_code, or a callback
# that reads `code` and `state`) but never references `iss`.
_AUTHCODE_FLOW_RE = re.compile(
    r"grant_type['\"]?\s*[:=]\s*['\"]?authorization_code"
    r"|\bexchange[_A-Za-z]*code[_A-Za-z]*token\b"
    r"|\bexchangeCodeForToken\b"
    r"|(?:args|query|params|query_params|searchParams|GET)\s*(?:\.get\s*\(|\[)\s*"
    r"['\"]code['\"]",
    re.IGNORECASE,
)
_ISS_PRESENT_RE = re.compile(r"\biss\b")

# RFC 8707 Resource Indicators (ratified MCP 2025-11-25 auth spec): the client
# MUST send the `resource` parameter on authorization + token requests so the
# issued token is audience-bound to the target MCP server. Fire AAK-OAUTH-007
# when the file drives an OAuth token-acquisition flow (or advertises an OAuth
# authorization/token endpoint) but never sets the `resource` parameter.
_TOKEN_ACQUISITION_RE = re.compile(
    r"grant_type['\"]?\s*[:=]"
    r"|\bauthorization_endpoint\b|\btoken_endpoint\b"
    r"|\bauthorize\s*\("
    r"|response_type['\"]?\s*[:=]\s*['\"]?code"
    r"|/(?:oauth2?/)?(?:authorize|token)\b",
    re.IGNORECASE,
)
# Presence of the RFC 8707 `resource` indicator (query param, JSON/dict key,
# kwarg/assignment, or an explicit RFC-8707 marker). Also matches the RFC 9728
# protected-resource-metadata `resource` field so an MCP server's own metadata
# is not flagged.
_RESOURCE_PARAM_RE = re.compile(
    r"[?&]resource="
    r"|['\"]resource['\"]\s*[:=]"
    r"|\bresource\s*=\s*"
    r"|\bresource_indicators?\b"
    r"|\bRFC\s?8707\b",
    re.IGNORECASE,
)

# RFC 9728 Protected Resource Metadata (ratified MCP 2025-11-25 auth spec, MUST):
# a protected MCP server advertises its authorization server(s) via PRM at
# `/.well-known/oauth-protected-resource` and clients discover auth from it
# instead of carrying a static credential. Fire AAK-OAUTH-008 when an MCP OAuth
# surface shows no PRM discovery — a remote-server config with an inline
# credential, or server source enforcing bearer auth. Runs independent of the
# client-flow `_OAUTH_HINT` (remote configs rarely contain flow keywords).
_MCP_REMOTE_RE = re.compile(
    r'"type"\s*:\s*"(?:streamable-?http|http|sse|streamable)"'
    r'|"transport"\s*:\s*"(?:streamable-?http|http|sse|streamable)"'
    r'|"url"\s*:\s*"https?://',
    re.IGNORECASE,
)
_MCP_INLINE_AUTH_RE = re.compile(
    r'"Authorization"\s*:'
    r"|\bBearer\b"
    r'|"auth"\s*:\s*\{'
    r"|\b--oauth\b"
    r'|"(?:access_token|api_key|token)"\s*:\s*"',
    re.IGNORECASE,
)
_MCP_SERVER_AUTH_RE = re.compile(
    r"\bWWW-Authenticate\b"
    r"|\bBearerAuthProvider\b|\bRequireAuthMiddleware\b|\brequire_auth\b",
    re.IGNORECASE,
)
_PRM_DISCOVERY_RE = re.compile(
    r"oauth-protected-resource"
    r"|protected[_-]?resource[_-]?metadata"
    r"|\bresource_metadata\b"
    r"|\bauthorization_servers\b"
    r"|\bRFC\s?9728\b",
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
    rel = str(path.relative_to(project_root))

    # AAK-OAUTH-008 runs first, independent of the client-flow hint: it targets
    # remote MCP server auth surfaces (configs + server source) that show no
    # RFC 9728 Protected Resource Metadata discovery.
    if not _PRM_DISCOVERY_RE.search(text):
        remote_auth = _MCP_REMOTE_RE.search(text) and _MCP_INLINE_AUTH_RE.search(text)
        anchor = _MCP_INLINE_AUTH_RE.search(text) if remote_auth else _MCP_SERVER_AUTH_RE.search(text)
        if anchor is not None:
            findings.append(
                make_finding(
                    "AAK-OAUTH-008",
                    rel,
                    "MCP OAuth surface has no RFC 9728 Protected Resource Metadata "
                    "discovery (`/.well-known/oauth-protected-resource`) — remote auth "
                    "relies on a static/embedded credential (resource-discovery gap; "
                    "2026-07-28 auth profile)",
                    line_number=find_line_number(text, anchor.group(0)),
                )
            )

    if not _OAUTH_HINT.search(text):
        return findings

    has_pkce = bool(_PKCE_PRESENT_RE.search(text))
    authorize_call = re.search(r"\bauthorize\s*\(|authorization_endpoint", text, re.IGNORECASE)

    if authorize_call and not has_pkce:
        findings.append(
            make_finding(
                "AAK-OAUTH-001",
                rel,
                "OAuth authorize call without PKCE fields (code_verifier/code_challenge)",
                line_number=find_line_number(text, authorize_call.group(0)),
            )
        )

    m_plain = _PKCE_PLAIN_RE.search(text)
    if m_plain:
        findings.append(
            make_finding(
                "AAK-OAUTH-002",
                rel,
                "PKCE code_challenge_method=plain (S256 is required)",
                line_number=find_line_number(text, m_plain.group(0)),
            )
        )

    m_tokenfwd = _TOKEN_FORWARD_RE.search(text)
    if m_tokenfwd:
        findings.append(
            make_finding(
                "AAK-OAUTH-003",
                rel,
                "Authorization header populated from inbound request (token passthrough)",
                line_number=find_line_number(text, m_tokenfwd.group(0)),
            )
        )

    m_redirect = _WILDCARD_REDIRECT_RE.search(text)
    if m_redirect:
        findings.append(
            make_finding(
                "AAK-OAUTH-004",
                rel,
                f"Wildcard or overly-broad redirect_uri: {m_redirect.group(0)!r}",
                line_number=find_line_number(text, m_redirect.group(0)),
            )
        )

    if _BEARER_ONLY_RE.search(text) and not _DPOP_HINT_RE.search(text) and "Authorization" in text:
        findings.append(
            make_finding(
                "AAK-OAUTH-005",
                rel,
                "Bearer-only auth; no DPoP/mTLS proof-of-possession detected",
            )
        )

    m_authcode = _AUTHCODE_FLOW_RE.search(text)
    if m_authcode and not _ISS_PRESENT_RE.search(text):
        findings.append(
            make_finding(
                "AAK-OAUTH-006",
                rel,
                "OAuth authorization-code response handled without validating the "
                "`iss` parameter (RFC 9207 / MCP 2026-07-28 SEP-2468)",
                line_number=find_line_number(text, m_authcode.group(0)),
            )
        )

    m_flow = _TOKEN_ACQUISITION_RE.search(text)
    if m_flow and not _RESOURCE_PARAM_RE.search(text):
        findings.append(
            make_finding(
                "AAK-OAUTH-007",
                rel,
                "OAuth flow builds authorization/token requests without the RFC 8707 "
                "`resource` parameter (Resource Indicators) — issued tokens are not "
                "audience-bound to this MCP server (MCP 2025-11-25 auth spec)",
                line_number=find_line_number(text, m_flow.group(0)),
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
