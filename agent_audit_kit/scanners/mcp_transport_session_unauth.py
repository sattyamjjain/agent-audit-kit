"""MCP transport accepts sessions with no caller credential — the "the token
points the wrong way" class.

The generic no-auth rule, ``AAK-MCP-HTTP-NOAUTH-SERVER-001``, asks whether the
file contains *any* authentication marker. That question has a blind spot, and
CVE-2026-82456 (argocd-mcp 0.8.0, CVSS 10.0) sits exactly inside it.

The server reads an operator credential from the environment and attaches it to
its **upstream** calls. Every reader — the generic rule included — sees
``Authorization:`` and concludes the server is authenticated. It is not. From
the advisory (GHSA-rp45-5x3v-48mr):

    The environment variable is an outbound Argo CD credential. It does not
    authenticate the caller.

The published shape is a fallback chain, where the inbound header is optional
and the outbound credential silently substitutes for it::

    const argocdApiToken =
      (req.headers['x-argocd-api-token'] as string) ||
      process.env.ARGOCD_API_TOKEN ||
      '';

A caller who sends no credential at all is therefore accepted, and the session
then executes the full tool surface with the operator's token — for argocd-mcp,
``create_application`` pointed at an attacker repository followed by
``sync_application``, i.e. arbitrary manifests applied to the destination
cluster.

**Two detections the generic rule cannot make.**

*The decorative credential.* ``_AUTH_MARKER_RE`` matches a bare
``Authorization:``, which an outbound header satisfies. The generic rule stands
down on precisely the files this one is for.

*The implicit bind.* The generic rule needs a literal ``0.0.0.0`` or ``::``.
argocd-mcp has neither: ``app.listen(port)`` at ``src/server/transport.ts:166``
binds every interface **because the host argument is absent**. That is a Node
semantic (``net.Server.listen`` defaults to ``::`` / ``0.0.0.0``), so the
implicit case is only ever inferred for JS/TS. Python's ``uvicorn.run`` and
``Flask.run`` default to loopback, and inferring a bind-all from a missing host
there would be wrong.

**Disjoint from the generic rule by construction.** A file where the generic
rule would itself fire — no auth marker *and* a bind/CORS signal it can see — is
left to it, so one defect is reported once. ``AAK-DNS-REBIND-001`` may fire
alongside this rule and should: missing Host validation and a missing inbound
credential are different defects with different fixes, and the advisory's
suggested-fix section lists both separately.

Scope note: this reads one file at a time, so an inbound check applied from a
separate middleware module is not seen. That limitation is recorded on the rule.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import in_skip_dir, find_line_number, make_finding, sub_up_to_last

# Reuse the generic rule's own predicates so the deferral below tracks it
# automatically rather than restating it and drifting.
from agent_audit_kit.scanners.mcp_server_auth import _AUTH_MARKER_RE
from agent_audit_kit.scanners.mcp_http_noauth_server import (
    _BIND_ALL_RE,
    _HTTP_SERVER_RE,
    _WILDCARD_CORS_RE,
)

_RULE_ID = "AAK-MCP-TRANSPORT-SESSION-UNAUTH-001"

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_PY_SUFFIXES = (".py",)

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# An MCP `/mcp` route, in either language family.
_MCP_ROUTE_RE = re.compile(
    r"""['"`]/mcp(?:[/?][^'"`]*)?['"`]""",
)

# --- (1) any-interface bind -------------------------------------------------

# Explicit all-interfaces literal. `_BIND_ALL_RE` (imported) covers the quoted
# forms; this adds the bracketed IPv6 and the bare `--host` flag spellings.
_EXPLICIT_ANY_RE = re.compile(
    r"""\[::\]|--host[=\s]+(?:0\.0\.0\.0|::)|['"`]0\.0\.0\.0['"`]|['"`]::['"`]""",
)

# A `.listen(...)` call, captured to the end of its line. The head of the
# argument list is enough to tell whether a host was supplied at all.
_JS_LISTEN_RE = re.compile(r"\.\s*listen\s*\(([^\n]{0,200})")

# A quoted value in that argument head that is plausibly a host: an IPv4
# literal, `localhost`, an IPv6 form, or a dotted name. A log string such as
# `"argocd-mcp listening"` has no dot and is not mistaken for one. Anything
# ambiguous is read as "a host was given", which suppresses rather than fires.
_HOST_LITERAL_RE = re.compile(
    r"""['"`](?:\d{1,3}(?:\.\d{1,3}){3}|localhost|::[\d:]*|[\w-]+(?:\.[\w-]+)+)['"`]""",
)
# `.listen({ port, host })` / `.listen({ host: ... })` — the object form.
_LISTEN_HOST_KEY_RE = re.compile(r"\bhost\b\s*[:=]")

# --- (2) an environment credential ------------------------------------------

_CRED_WORD = r"(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CRED(?:ENTIAL)?S?|PAT|APIKEY)"
_PROCESS_ENV = r"process\s*\.\s*env\s*(?:\.\s*|\[\s*['\"`])[A-Za-z0-9_]*"
_ENV_CRED_RE = re.compile(
    _PROCESS_ENV + _CRED_WORD
    + r"|os\s*\.\s*environ\s*(?:\.\s*get\s*\(\s*|\[\s*)['\"][A-Za-z0-9_]*" + _CRED_WORD
    + r"|os\s*\.\s*getenv\s*\(\s*['\"][A-Za-z0-9_]*" + _CRED_WORD,
    re.IGNORECASE,
)

# --- (3) the credential points outward, not inward --------------------------

# The published shape: an inbound header read that falls back to an environment
# credential. `[^;]` keeps the match inside one statement in semicolon'd code;
# the length caps bound it where semicolons are omitted.
_HEADER_TO_ENV_FALLBACK_RE = re.compile(
    r"(?:req|request|ctx|c)\s*\.\s*(?:headers?|get)\b[^;]{0,140}?"
    r"\|\|\s*[^;]{0,60}?"
    + _PROCESS_ENV + _CRED_WORD,
    re.IGNORECASE | re.DOTALL,
)

# An `Authorization` header being *constructed* for an outbound request — the
# marker that silences the generic rule while authenticating nobody inbound.
_OUTBOUND_AUTH_RE = re.compile(
    r"headers\s*[:=]\s*[{(][^})]{0,300}?Authorization"
    r"|Authorization['\"`]?\s*[:=]\s*[f`'\"][^\n]{0,40}?(?:Bearer|Token|\$\{|\{)",
    re.IGNORECASE | re.DOTALL,
)

# --- inbound, per-caller checks (suppressors) -------------------------------
#
# Deliberately narrow: every entry names a check applied to the *caller*. A bare
# `Authorization:` is absent on purpose — that is the marker this rule exists to
# see through.
_INBOUND_AUTH_RE = re.compile(
    r"""
      @require_auth\b | @auth_required\b | @login_required\b
    | @authenticated\b | @jwt_required\b | @azure_ad_required\b
    | requireAuth\s*\( | passport\.authenticate\s*\( | expressjwt\s*\(
    | verify_jwt\s*\( | verifyToken\s*\( | jwksClient\s*\(
    | authenticateRequest\s*\( | authMiddleware\b | requireBearer\w*\s*\(
    | HTTPBearer\s*\( | Security\s*\( | Depends\s*\(\s*\w*(?:auth|verify|current_user)
    | hostHeaderValidation\s*\( | createMcpExpressApp\s*\(
    | enableDnsRebindingProtection\s*:\s*true
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _strip_ts_comments(text: str) -> str:
    return _TS_LINE_COMMENT_RE.sub(" ", sub_up_to_last(_TS_BLOCK_COMMENT_RE, " ", text, "*/"))


def _is_mcp_http_server(text: str) -> bool:
    return bool(_HTTP_SERVER_RE.search(text) or _MCP_ROUTE_RE.search(text))


def _any_interface_bind(text: str, *, is_js: bool) -> str | None:
    """How the transport reaches every interface, or ``None`` if it does not.

    Returns ``"explicit"`` for a written-out ``0.0.0.0`` / ``::``, or
    ``"implicit"`` for a JS/TS ``.listen(port)`` with the host argument omitted
    — which is how CVE-2026-82456 binds, with no such literal in the source.
    """
    if _EXPLICIT_ANY_RE.search(text) or _BIND_ALL_RE.search(text):
        return "explicit"
    if not is_js:
        # Python web servers default to loopback; absence of a host argument
        # says nothing there, so it is never inferred.
        return None
    for match in _JS_LISTEN_RE.finditer(text):
        args = match.group(1)
        if _HOST_LITERAL_RE.search(args) or _LISTEN_HOST_KEY_RE.search(args):
            continue
        return "implicit"
    return None


def _generic_rule_owns(text: str) -> bool:
    """True when ``AAK-MCP-HTTP-NOAUTH-SERVER-001`` reports this file itself.

    It fires on no-auth-marker plus a bind/CORS signal of its own. Standing down
    there keeps one defect to one rule id.
    """
    if _AUTH_MARKER_RE.search(text):
        return False
    return bool(_BIND_ALL_RE.search(text) or _WILDCARD_CORS_RE.search(text))


def _classify(text: str, *, is_js: bool) -> tuple[str, str] | None:
    """Return ``(bind_kind, why)`` when the conjunction holds, else ``None``."""
    if not _is_mcp_http_server(text):
        return None

    bind = _any_interface_bind(text, is_js=is_js)
    if bind is None:
        return None

    if _generic_rule_owns(text):
        return None

    fallback = bool(_HEADER_TO_ENV_FALLBACK_RE.search(text))
    if not fallback:
        # Without the fallback chain, require an environment credential that is
        # demonstrably spent outbound, and no inbound check anywhere.
        if not (_ENV_CRED_RE.search(text) and _OUTBOUND_AUTH_RE.search(text)):
            return None
        if _INBOUND_AUTH_RE.search(text):
            return None
        why = (
            "an environment credential is attached to upstream requests, but no "
            "inbound check gates the MCP session"
        )
    else:
        # The fallback chain defeats an inbound header read: the header is
        # present in the source and optional at runtime, so a caller who sends
        # nothing is still served. An inbound-auth marker does not clear this.
        why = (
            "the inbound credential header falls back to an environment "
            "credential, so a caller that sends none is still accepted"
        )
    return bind, why


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP HTTP transports that bind every interface and authenticate
    no caller.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _JS_SUFFIXES + _PY_SUFFIXES:
            continue
        if in_skip_dir(path, project_root):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        is_js = path.suffix in _JS_SUFFIXES
        text = _strip_ts_comments(raw) if is_js else raw

        result = _classify(text, is_js=is_js)
        if result is None:
            continue
        bind, why = result

        exposure = (
            "binds 0.0.0.0/:: explicitly"
            if bind == "explicit"
            else "calls .listen(port) with no host, which binds every interface"
        )
        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                f"MCP HTTP transport {exposure} and {why} — any host that can "
                f"reach the listener executes the full tool surface with the "
                f"operator's stored credential (CVE-2026-82456 argocd-mcp class, "
                f"CVSS 10.0). Require a separate inbound credential for network "
                f"transports and bind 127.0.0.1 by default; an environment token "
                f"is an outbound credential and must never authenticate a caller."
            ),
            find_line_number(raw, ".listen(") or find_line_number(raw, "0.0.0.0"),
        ))

    return findings, scanned_files
