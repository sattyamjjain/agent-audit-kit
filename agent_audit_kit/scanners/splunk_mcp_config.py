"""AAK-SPLUNK-MCP-TOKEN-LEAK-001 — config-side variant of CVE-2026-20205.

v0.3.4's AAK-SPLUNK-TOKLOG-001 fires on token-shaped values in log
sinks at runtime. This rule fires on the *configuration* that makes
the runtime leak inevitable: a splunk-mcp-server config (inputs.conf,
splunk-mcp.yaml, anything under a directory named for splunk and mcp, such
as splunk-mcp/ or splunk-mcp-server/) that routes a token-bearing
source into the `_internal` or `_audit` index.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from agent_audit_kit.models import Finding

from ._helpers import CONFIG_MAX_BYTES, find_line_number, in_skip_dir, load_yaml, make_finding, read_text_capped


_TOKEN_SOURCETYPE_RE = re.compile(
    r"""
    sourcetype\s*=\s*
    (?:splunk_session|mcp_auth|bearer|access_token|session_token|jwt)
    """,
    re.VERBOSE | re.IGNORECASE,
)
_INTERNAL_INDEX_RE = re.compile(
    r"""
    index\s*[:=]\s*['"]?(_internal|_audit|_introspection)['"]?
    """,
    re.VERBOSE | re.IGNORECASE,
)


_NAME_WORD_SPLIT_RE = re.compile(r"[-_.]+")


def _names_splunk_mcp(part: str) -> bool:
    """A directory named for both splunk and mcp, in either order: `splunk-mcp`,
    `splunk_mcp_server`, `splunk-mcp-server` (the server's own repository name, so a
    vendored copy below the scan root), `mcp-server-splunk`."""
    return {"splunk", "mcp"} <= set(_NAME_WORD_SPLIT_RE.split(part.lower()))


def _is_splunk_mcp_path(path: Path, project_root: Path) -> bool:
    rel = path.relative_to(project_root)
    if any(_names_splunk_mcp(part) for part in rel.parts[:-1]):
        return True
    name = path.name.lower()
    return name in {"inputs.conf", "splunk-mcp.yaml", "splunk-mcp.yml", "splunk_mcp.yaml", "splunk_mcp.yml"}


def _yaml_routes_token_to_internal(text: str, path: Path) -> bool:
    try:
        data = load_yaml(text, path)
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    inputs = data.get("inputs") or data.get("sourcetypes") or []
    if not isinstance(inputs, list):
        return False
    for entry in inputs:
        if not isinstance(entry, dict):
            continue
        index = (entry.get("index") or "").strip()
        sourcetype = (entry.get("sourcetype") or "").strip().lower()
        if index in ("_internal", "_audit", "_introspection") and (
            sourcetype in {"splunk_session", "mcp_auth", "bearer", "access_token", "session_token", "jwt"}
            or "token" in sourcetype
        ):
            return True
    return False


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root):
            continue
        if not _is_splunk_mcp_path(path, project_root):
            continue
        try:
            text = read_text_capped(path, CONFIG_MAX_BYTES, errors="replace")
        except OSError:
            continue

        rel = str(path.relative_to(project_root))
        suspicious = False
        if path.suffix in (".yaml", ".yml"):
            suspicious = _yaml_routes_token_to_internal(text, path)
        # Always run the line-pair regex too — picks up inputs.conf and
        # mixed YAML files where keys aren't structured.
        if not suspicious:
            has_token = bool(_TOKEN_SOURCETYPE_RE.search(text))
            has_internal = bool(_INTERNAL_INDEX_RE.search(text))
            suspicious = has_token and has_internal

        if suspicious:
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-SPLUNK-MCP-TOKEN-LEAK-001",
                rel,
                "splunk-mcp-server config routes a token-bearing "
                "sourcetype into the _internal / _audit index. "
                "CVE-2026-20205 origin.",
                line_number=find_line_number(text, "_internal")
                or find_line_number(text, "sourcetype"),
            ))
    return findings, scanned
