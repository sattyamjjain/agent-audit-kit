"""AAK-TOXICFLOW-001 — toxic-flow source/sink pair scoring.

Snyk Agent Scan parity. Discover every tool the agent project exposes
(MCP servers in `.mcp.json` + skills in `.claude/skills/` + first-party
tools the codebase imports) and emit a HIGH finding for every
(sensitive_source, external_sink) pair listed in
`agent_audit_kit/data/toxic_flow_pairs.yml` — unless the pair appears
in `.aak-toxic-flow-trust.yml` with a non-empty justification.

Behind a feature flag for v0.3.5: requires `AAK_TOXIC_FLOW=1` in the
environment to fire. Full deny-graph design review queues for v0.4.0.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable

import yaml

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PAIRS_PATH = _DATA_DIR / "toxic_flow_pairs.yml"


def _load_pairs() -> dict:
    if not _PAIRS_PATH.is_file():
        return {"sources": {}, "sinks": {}, "pairs": []}
    try:
        return yaml.safe_load(_PAIRS_PATH.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {"sources": {}, "sinks": {}, "pairs": []}


def _flag_enabled() -> bool:
    return os.environ.get("AAK_TOXIC_FLOW", "").strip() not in ("", "0", "false", "False")


def _load_trust(project_root: Path) -> set[tuple[str, str]]:
    trust_path = project_root / ".aak-toxic-flow-trust.yml"
    if not trust_path.is_file():
        return set()
    try:
        data = yaml.safe_load(trust_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return set()
    out: set[tuple[str, str]] = set()
    for entry in data.get("trust", []) or []:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        sink = entry.get("sink")
        justification = entry.get("justification", "")
        if not source or not sink or not isinstance(justification, str) or not justification.strip():
            continue
        out.add((source, sink))
    return out


def _discover_mcp_tools(project_root: Path) -> set[str]:
    """Collect tool/server identifiers from MCP config files."""
    tools: set[str] = set()
    for cfg in (
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".amazonq/mcp.json",
        "mcp.json",
    ):
        p = project_root / cfg
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            continue
        for name, cfg_data in servers.items():
            tools.add(name)
            if isinstance(cfg_data, dict):
                args = cfg_data.get("args")
                if isinstance(args, list):
                    for arg in args:
                        if isinstance(arg, str):
                            tools.add(arg)
    return tools


_TOOL_DECORATOR_RE = re.compile(
    r"""
    @(?:mcp\s*\.\s*tool|server\s*\.\s*tool|tool|langchain\s*\.\s*tools\s*\.\s*tool)
    \s*\(?\s*[\)\n]
    """,
    re.VERBOSE,
)
_DEF_NAME_RE = re.compile(r"def\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(")


def _discover_repo_tools(project_root: Path) -> set[str]:
    """Names of @tool / @mcp.tool decorated functions in the repo."""
    tools: set[str] = set()
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "@tool" not in text and "@mcp.tool" not in text and "@server.tool" not in text:
            continue
        # Cheap pass: pair @-decorator with the immediately following def.
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if _TOOL_DECORATOR_RE.search(line):
                # Look ahead for the def in the next 3 lines.
                for off in range(1, 4):
                    if i + off >= len(lines):
                        break
                    m = _DEF_NAME_RE.search(lines[i + off])
                    if m:
                        tools.add(m.group(1))
                        break
    return tools


def _classify(tool_id: str, family_map: dict[str, list[str]]) -> set[str]:
    """Return all family names that match this tool identifier."""
    matched: set[str] = set()
    lower = tool_id.lower()
    for family, members in (family_map or {}).items():
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, str):
                continue
            ml = member.lower()
            if ml == lower or ml in lower or lower.endswith(ml):
                matched.add(family)
                break
    return matched


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    if not _flag_enabled():
        return [], set()

    pairs_cfg = _load_pairs()
    sources_map = pairs_cfg.get("sources") or {}
    sinks_map = pairs_cfg.get("sinks") or {}
    pair_rules: list[dict] = pairs_cfg.get("pairs") or []
    trust = _load_trust(project_root)

    scanned: set[str] = set()
    discovered = _discover_mcp_tools(project_root) | _discover_repo_tools(project_root)
    if not discovered:
        return [], scanned

    # Map each discovered tool to its source/sink families.
    source_families: dict[str, set[str]] = {}
    sink_families: dict[str, set[str]] = {}
    for tool in discovered:
        sources = _classify(tool, sources_map)
        sinks = _classify(tool, sinks_map)
        if sources:
            source_families[tool] = sources
        if sinks:
            sink_families[tool] = sinks

    findings: list[Finding] = []
    for rule in pair_rules:
        if not isinstance(rule, dict):
            continue
        source_fam = rule.get("source")
        sink_fam = rule.get("sink")
        if not source_fam or not sink_fam:
            continue
        if (source_fam, sink_fam) in trust:
            continue
        source_tools = sorted(t for t, fams in source_families.items() if source_fam in fams)
        sink_tools = sorted(t for t, fams in sink_families.items() if sink_fam in fams)
        if not source_tools or not sink_tools:
            continue
        evidence = (
            f"Toxic flow: source family `{source_fam}` "
            f"({', '.join(source_tools)}) paired with sink family "
            f"`{sink_fam}` ({', '.join(sink_tools)}). The LLM can chain "
            "these tools — add an entry to `.aak-toxic-flow-trust.yml` "
            "with a justification, or remove one side of the pair."
        )
        findings.append(make_finding(
            "AAK-TOXICFLOW-001",
            ".mcp.json",
            evidence,
        ))
    if findings:
        scanned.add(".mcp.json")
    return findings, scanned


def discovered_tools(project_root: Path) -> Iterable[str]:
    """Helper for `agent-audit-kit toxic-flow --explain` (future CLI)."""
    return sorted(_discover_mcp_tools(project_root) | _discover_repo_tools(project_root))
