"""MCP 2026-07-28 deprecated-feature scanner — AAK-MCP-DEPRECATED-001..003.

The MCP 2026-07-28 spec release candidate ships the protocol's first formal
deprecation policy (SEP-2596: a minimum 12-month window between deprecation and
removal) and, under it, annotation-deprecates three core features via SEP-2577:

  - ``roots``    (AAK-MCP-DEPRECATED-001) -> pass workspace paths as tool params.
  - ``sampling`` (AAK-MCP-DEPRECATED-002) -> call the LLM provider API directly.
  - ``logging``  (AAK-MCP-DEPRECATED-003) -> emit to stderr / OpenTelemetry.

They stay functional for at least a year (runway to ~mid-2027) but are on the
removal path. This scanner flags continued use of each deprecated surface —
across MCP config files, manifests, and server/client source — so authors can
migrate inside the window instead of breaking on removal.

Detection is deliberately tight to avoid firing on ordinary code (e.g. Python's
stdlib ``logging`` / ``logger.setLevel``): the MCP method strings
(``roots/list``, ``sampling/createMessage``, ``logging/setLevel``) and the SDK
type names are MCP-unique and fire on their own; the softer markers (SDK method
aliases, a ``capabilities`` object key) require an MCP context in the file.

Source: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_CAP_TO_RULE = {
    "roots": "AAK-MCP-DEPRECATED-001",
    "sampling": "AAK-MCP-DEPRECATED-002",
    "logging": "AAK-MCP-DEPRECATED-003",
}

_LANG_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".java", ".kt"}
_CONFIG_NAMES = {
    ".mcp.json", "mcp.json", "claude_desktop_config.json",
    ".cursor/mcp.json", ".vscode/mcp.json", ".windsurf/mcp.json",
    ".amazonq/mcp.json", ".roo/mcp.json", ".kiro/mcp.json",
    "package.json", "pyproject.toml",
}
_CONFIG_GLOBS = ("*.mcp.json", "*.mcp.yaml", "*.mcp.yml")
_MAX_FILE_BYTES = 1_000_000

# Any MCP signal in the file; gates the softer per-feature markers below.
_MCP_HINT = re.compile(
    r"modelcontextprotocol|FastMCP|McpServer|@mcp\.|mcp\.server|from\s+mcp\b"
    r"|import\s+mcp\b|ServerCapabilities|mcpServers|@modelcontextprotocol/",
    re.IGNORECASE,
)

# MCP-unique markers — these fire on their own (no hint required).
_STRONG = {
    "AAK-MCP-DEPRECATED-001": re.compile(
        r"\broots/list\b|notifications/roots/list_changed"
        r"|\bListRootsRequest\b|\bListRootsResult\b|\bsend_roots_list_changed\b"
        r"|\bsendRootsListChanged\b|\bRootsListChangedNotification\b"
    ),
    "AAK-MCP-DEPRECATED-002": re.compile(
        r"\bsampling/createMessage\b|\bCreateMessageRequest(?:Schema)?\b"
        r"|\bRequestSampling\b"
    ),
    "AAK-MCP-DEPRECATED-003": re.compile(
        r"\blogging/setLevel\b|\bLoggingMessageNotification\b"
        r"|\bSetLevelRequest(?:Schema)?\b|\bLoggingLevel\b"
    ),
}

# Softer markers — require an MCP hint in the same file.
_WEAK = {
    "AAK-MCP-DEPRECATED-001": re.compile(
        r"\blist_roots\s*\(|\blistRoots\s*\(|capabilities\s*[:=]\s*\{[^}]*\broots\b"
        r"|ServerCapabilities\s*\([^)]*\broots\s*="
    ),
    "AAK-MCP-DEPRECATED-002": re.compile(
        r"\bcreate_message\s*\(|\.sampling\.create\s*\("
        r"|capabilities\s*[:=]\s*\{[^}]*\bsampling\b"
        r"|ServerCapabilities\s*\([^)]*\bsampling\s*="
    ),
    "AAK-MCP-DEPRECATED-003": re.compile(
        r"capabilities\s*[:=]\s*\{[^}]*\blogging\b"
        r"|ServerCapabilities\s*\([^)]*\blogging\s*="
    ),
}

_EVIDENCE = {
    "AAK-MCP-DEPRECATED-001": "Deprecated MCP `roots` capability in use (SEP-2577) — migrate to tool params / config before removal.",
    "AAK-MCP-DEPRECATED-002": "Deprecated MCP `sampling` capability in use (SEP-2577) — call the LLM provider API directly before removal.",
    "AAK-MCP-DEPRECATED-003": "Deprecated MCP `logging` capability in use (SEP-2577) — use stderr / OpenTelemetry before removal.",
}


def _line_of(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def _walk_capabilities(obj: object, found: set[str]) -> None:
    """Collect deprecated capability keys declared under any `capabilities`
    object anywhere in a parsed JSON structure (handles dict or list form)."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "capabilities":
                if isinstance(value, dict):
                    found.update(c for c in value if c in _CAP_TO_RULE)
                elif isinstance(value, list):
                    found.update(c for c in value if isinstance(c, str) and c in _CAP_TO_RULE)
            _walk_capabilities(value, found)
    elif isinstance(obj, list):
        for item in obj:
            _walk_capabilities(item, found)


def _json_capability_hits(text: str) -> set[str]:
    """Rule IDs for deprecated capabilities declared in a JSON `capabilities`
    block (precise; multi-key safe). Empty when the file is not JSON."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    found: set[str] = set()
    _walk_capabilities(data, found)
    return {_CAP_TO_RULE[c] for c in found}


def _check_text(text: str, has_hint: bool) -> dict[str, int]:
    """Return {rule_id: line} for each deprecated feature matched in text.

    Merges regex markers (source-side) with a JSON `capabilities` walk
    (config-side, multi-key safe). One entry per feature.
    """
    out: dict[str, int] = {}
    for rule_id, strong in _STRONG.items():
        m = strong.search(text)
        if m is None and has_hint:
            m = _WEAK[rule_id].search(text)
        if m is not None:
            out[rule_id] = _line_of(text, m.start())

    for rule_id in _json_capability_hits(text):
        if rule_id not in out:
            cap = next(c for c, r in _CAP_TO_RULE.items() if r == rule_id)
            out[rule_id] = find_line_number(text, f'"{cap}"') or 1
    return out


def _candidate_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    seen: set[Path] = set()
    for name in _CONFIG_NAMES:
        p = project_root / name
        if p.is_file() and p not in seen:
            out.append(p)
            seen.add(p)
    for pattern in _CONFIG_GLOBS:
        for p in project_root.rglob(pattern):
            if p.is_file() and p not in seen and not any(part in SKIP_DIRS for part in p.parts):
                out.append(p)
                seen.add(p)
    for p in project_root.rglob("*"):
        if p.suffix in _LANG_EXTS and p.is_file() and p not in seen:
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            out.append(p)
            seen.add(p)
    return out


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP 2026-07-28 deprecated features (roots / sampling / logging).

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()

    for path in _candidate_files(project_root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        has_hint = bool(_MCP_HINT.search(text))
        for rule_id, line in _check_text(text, has_hint).items():
            findings.append(make_finding(rule_id, rel, _EVIDENCE[rule_id], line))

    return findings, scanned
