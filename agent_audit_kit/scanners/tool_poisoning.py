from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

# ---- MCP config file discovery (mirrors mcp_config.py) ----
_MCP_CONFIG_FILES: list[str] = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    "mcp.json",
]

# ---- AAK-POISON-001: Invisible Unicode categories and explicit codepoints ----
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Mn"})
_INVISIBLE_CODEPOINTS = frozenset({
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u2060",  # word joiner
    "\ufeff",  # BOM / zero-width no-break space
    "\u202a",  # left-to-right embedding
    "\u202b",  # right-to-left embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # left-to-right override
    "\u202e",  # right-to-left override
})

# ---- AAK-POISON-002: Prompt injection patterns ----
_PROMPT_INJECTION_RE = re.compile(
    r"ignore\s+previous|"
    r"\bsystem\s*:|"
    r"\byou\s+are\b|"
    r"\bforget\b|"
    r"new\s+instructions|"
    r"\boverride\b|"
    r"admin\s+mode|"
    r"<hidden>|"
    r"<system>",
    re.IGNORECASE,
)

# ---- AAK-POISON-003: Cross-tool reference patterns ----
_CROSS_TOOL_RE = re.compile(
    r"before\s+calling|"
    r"first\s+call|"
    r"after\s+using|"
    r"then\s+use|"
    r"\binvoke\b",
    re.IGNORECASE,
)

# ---- AAK-POISON-004: Encoded content patterns ----
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_SEQUENCE_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){3,}")
_URL_ENCODED_RE = re.compile(r"(%[0-9a-fA-F]{2}){3,}")

# ---- AAK-POISON-006: URL / file path patterns ----
_URL_RE = re.compile(r"https?://[^\s\)>\]\"']+", re.IGNORECASE)
_FILE_PATH_RE = re.compile(
    r"/[a-zA-Z0-9_./-]{3,}|"
    r"~/[a-zA-Z0-9_./-]*|"
    r"[A-Z]:\\[^\s]+",
)

# Max length for AAK-POISON-005
_MAX_DESCRIPTION_LENGTH = 500


def _find_mcp_configs(project_root: Path) -> list[Path]:
    """Discover MCP configuration files in the project."""
    found: list[Path] = []
    for name in _MCP_CONFIG_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    # Recursively find any *mcp*.json
    for p in project_root.rglob("*mcp*.json"):
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    return found


def _has_invisible_unicode(text: str) -> list[tuple[str, int]]:
    """Return list of (codepoint_repr, char_index) for invisible Unicode in *text*."""
    hits: list[tuple[str, int]] = []
    for idx, ch in enumerate(text):
        if ch in _INVISIBLE_CODEPOINTS or unicodedata.category(ch) in _INVISIBLE_CATEGORIES:
            hits.append((f"U+{ord(ch):04X}", idx))
    return hits


def _extract_tool_descriptions(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Extract (server_name, tool_name, description) triples from MCP config.

    Handles several config shapes:
      - mcpServers.<name>.tools[].{name, description}
      - mcpServers.<name>.toolDescriptions.<toolName>
      - mcpServers.<name>.tools[]  (string items treated as name+description)
    """
    results: list[tuple[str, str, str]] = []
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return results

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue

        # Shape 1: tools as array of objects with name/description
        tools = server_cfg.get("tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    t_name = tool.get("name", "<unnamed>")
                    t_desc = tool.get("description", "")
                    if isinstance(t_desc, str) and t_desc:
                        results.append((server_name, str(t_name), t_desc))
                    # Also check inputSchema.description
                    input_schema = tool.get("inputSchema", {})
                    if isinstance(input_schema, dict):
                        schema_desc = input_schema.get("description", "")
                        if isinstance(schema_desc, str) and schema_desc:
                            results.append((server_name, f"{t_name}/inputSchema", schema_desc))

        # Shape 2: toolDescriptions map
        tool_descriptions = server_cfg.get("toolDescriptions", {})
        if isinstance(tool_descriptions, dict):
            for t_name, t_desc in tool_descriptions.items():
                if isinstance(t_desc, str) and t_desc:
                    results.append((server_name, str(t_name), t_desc))

    return results


def _check_description(
    server_name: str,
    tool_name: str,
    description: str,
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """Run all six POISON rules against a single tool description."""
    findings: list[Finding] = []
    ctx = f"Server '{server_name}', tool '{tool_name}'"

    # AAK-POISON-001: Invisible Unicode
    invisible_hits = _has_invisible_unicode(description)
    if invisible_hits:
        codepoints = ", ".join(cp for cp, _ in invisible_hits[:5])
        findings.append(make_finding(
            "AAK-POISON-001",
            rel_path,
            f"{ctx}: invisible chars {codepoints}",
            find_line_number(raw_text, tool_name),
        ))

    # AAK-POISON-002: Prompt injection
    for match in _PROMPT_INJECTION_RE.finditer(description):
        findings.append(make_finding(
            "AAK-POISON-002",
            rel_path,
            f"{ctx}: injection pattern '{match.group().strip()}'",
            find_line_number(raw_text, match.group().strip()[:40]),
        ))

    # AAK-POISON-003: Cross-tool references
    for match in _CROSS_TOOL_RE.finditer(description):
        findings.append(make_finding(
            "AAK-POISON-003",
            rel_path,
            f"{ctx}: cross-tool ref '{match.group().strip()}'",
            find_line_number(raw_text, match.group().strip()[:40]),
        ))

    # AAK-POISON-004: Encoded content
    has_encoded = False
    if _BASE64_RE.search(description):
        has_encoded = True
        findings.append(make_finding(
            "AAK-POISON-004",
            rel_path,
            f"{ctx}: base64-like content detected",
            find_line_number(raw_text, tool_name),
        ))
    if _HEX_SEQUENCE_RE.search(description):
        has_encoded = True
        findings.append(make_finding(
            "AAK-POISON-004",
            rel_path,
            f"{ctx}: hex-encoded content detected",
            find_line_number(raw_text, tool_name),
        ))
    if _URL_ENCODED_RE.search(description) and not has_encoded:
        findings.append(make_finding(
            "AAK-POISON-004",
            rel_path,
            f"{ctx}: URL-encoded content detected",
            find_line_number(raw_text, tool_name),
        ))

    # AAK-POISON-005: Excessive description length
    if len(description) > _MAX_DESCRIPTION_LENGTH:
        findings.append(make_finding(
            "AAK-POISON-005",
            rel_path,
            f"{ctx}: description length {len(description)} chars (max {_MAX_DESCRIPTION_LENGTH})",
            find_line_number(raw_text, tool_name),
        ))

    # AAK-POISON-006: URLs or file paths
    for match in _URL_RE.finditer(description):
        findings.append(make_finding(
            "AAK-POISON-006",
            rel_path,
            f"{ctx}: URL in description '{match.group()[:120]}'",
            find_line_number(raw_text, match.group()[:40]),
        ))
    for match in _FILE_PATH_RE.finditer(description):
        findings.append(make_finding(
            "AAK-POISON-006",
            rel_path,
            f"{ctx}: file path in description '{match.group()[:120]}'",
            find_line_number(raw_text, match.group()[:40]),
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan MCP config files for tool description poisoning.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for config_path in _find_mcp_configs(project_root):
        try:
            raw_text = config_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = (
            str(config_path.relative_to(project_root))
            if config_path.is_relative_to(project_root)
            else str(config_path)
        )
        scanned_files.add(rel_path)

        for server_name, tool_name, description in _extract_tool_descriptions(data):
            findings.extend(
                _check_description(server_name, tool_name, description, rel_path, raw_text)
            )

    return findings, scanned_files
