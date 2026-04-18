"""OAuth 2.1 misconfiguration scanner.

Fires AAK-OAUTH-001..005. MCP spec 2025-11-25 makes OAuth 2.1 mandatory
with PKCE+S256; this scanner pattern-matches violations in source code
and config files.
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
    if not _OAUTH_HINT.search(text):
        return findings
    rel = str(path.relative_to(project_root))

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

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
