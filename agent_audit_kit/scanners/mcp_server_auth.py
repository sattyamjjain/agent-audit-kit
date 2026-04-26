"""AAK-AZURE-MCP-NOAUTH-001 — server-author Azure MCP missing auth.

Mirror of v0.3.5's AAK-AZURE-MCP-001 (consumer-side) for repos that
*publish* an Azure-MCP-shaped server. Detects:

1. The repo declares Azure MCP server identity in
   `pyproject.toml` / `package.json` (keywords or package name).
2. The repo defines `/mcp/*` route handlers in Python (FastAPI /
   Flask) or TS (Express / Fastify / Hono).
3. None of those route handlers carry an auth marker
   (`@require_auth`, `@auth_required`, `Authorize` middleware,
   `verify_jwt`, mTLS check, Azure-AD/`DefaultAzureCredential`
   reference).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_PY_MCP_ROUTE_RE = re.compile(
    r"""
    @(?:app|router|api)\s*\.\s*(?:get|post|put|delete|route|websocket)\s*\(
    \s*['"](?P<path>/mcp[^'"]*)['"]
    """,
    re.VERBOSE,
)
_TS_MCP_ROUTE_RE = re.compile(
    r"""
    \b(?:app|router|server|api|fastify)\s*\.\s*(?:get|post|put|delete|route|use)\s*\(
    \s*['"`](?P<path>/mcp[^'"`]*)['"`]
    """,
    re.VERBOSE,
)

_AUTH_MARKER_RE = re.compile(
    r"""
    (?:
        @require_auth\b
      | @auth_required\b
      | @login_required\b
      | @authenticated\b
      | @jwt_required\b
      | @azure_ad_required\b
      | verify_jwt\s*\(
      | DefaultAzureCredential
      | ManagedIdentityCredential
      | WorkloadIdentityCredential
      | requireAuth\s*\(
      | passport\.authenticate\s*\(
      | bearerStrategy\b
      | clientCertificate\b
      | mtls\b
      | x-functions-key
      | Authorization\s*[:=]
      | jwksClient\s*\(
    )
    """,
    re.VERBOSE,
)


_AZURE_HINT_RE = re.compile(
    r"""
    (?:
        @azure/mcp-server
      | azure-mcp-server
      | mcp-server-azure
      | azure[-_]?mcp[-_]?server
      | mcp\.azurewebsites\.net
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _is_azure_mcp_repo(project_root: Path) -> bool:
    for name in ("pyproject.toml", "package.json", "Cargo.toml", "pom.xml"):
        p = project_root / name
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _AZURE_HINT_RE.search(text):
            return True
        if name == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                kw = data.get("keywords") or []
                if isinstance(kw, list) and any(
                    isinstance(k, str) and _AZURE_HINT_RE.search(k) for k in kw
                ):
                    return True
    return False


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    if not _is_azure_mcp_repo(project_root):
        return findings, scanned

    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            matches = list(_PY_MCP_ROUTE_RE.finditer(text))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            matches = list(_TS_MCP_ROUTE_RE.finditer(text))
        else:
            continue
        if not matches:
            continue
        # Whole-file auth-marker check is deliberately coarse — if the
        # file has *any* auth marker, assume the route handler is wired.
        if _AUTH_MARKER_RE.search(text):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        for m in matches:
            line = text.count("\n", 0, m.start()) + 1
            findings.append(make_finding(
                "AAK-AZURE-MCP-NOAUTH-001",
                rel,
                f"`{m.group('path')}` route handler has no auth marker "
                "(no @require_auth / verify_jwt / DefaultAzureCredential "
                "/ Authorization header check) in the same file. "
                "CVE-2026-32211 server-side default.",
                line_number=line,
            ))
            break  # one finding per file
    return findings, scanned
