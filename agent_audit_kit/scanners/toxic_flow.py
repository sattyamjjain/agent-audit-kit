"""AAK-TOXICFLOW-001 — toxic-flow source/sink pair scoring.

Snyk Agent Scan parity. Discover every tool the agent project exposes
(MCP servers in `.mcp.json` and the other MCP config files, VS Code's
`servers` object included, + skills in `.claude/skills/` + first-party
tools the codebase imports) and emit a HIGH finding for every
(sensitive_source, external_sink) pair listed in
`agent_audit_kit/data/toxic_flow_pairs.yml` — unless the pair appears
in `.aak-toxic-flow-trust.yml` with a non-empty justification.

Off by default: requires `AAK_TOXIC_FLOW=1` in the environment to fire.
That was introduced as a v0.3.5 temporary measure and is still the
state at v0.3.86, so read it as the standing position rather than a
countdown. The deny-graph design review it was waiting on has not
happened, and until it does this rule pairs sources and sinks from a
static YAML list, which over-reports on any project that legitimately
does both.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable

import yaml

from agent_audit_kit.models import Finding

from ._helpers import in_skip_dir, iter_mcp_servers, loads_jsonc, make_finding


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


_MCP_CONFIG_FILES: tuple[str, ...] = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    "mcp.json",
)


def _mcp_tool_origins(project_root: Path) -> tuple[dict[str, str], set[str]]:
    """Tool/server identifiers from MCP config files, each with the file it came from.

    Returns ``(origins, parsed)``: ``origins`` maps an identifier to the first
    config that declared it, and ``parsed`` is every config file read. The
    origin is what a finding is reported against. It used to be `.mcp.json`
    whatever the pair's source, which once `servers` was read would have named
    a file a VS Code-only project does not have.
    """
    origins: dict[str, str] = {}
    parsed: set[str] = set()
    for cfg in _MCP_CONFIG_FILES:
        p = project_root / cfg
        if not p.is_file():
            continue
        try:
            data = loads_jsonc(p.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        parsed.add(cfg)
        # VS Code's `servers` map counts too: `.vscode/mcp.json` was on the
        # list while only `mcpServers` was read, so a VS Code project exposed
        # no MCP tools here. An entry that is not an object declares no
        # server, so its name is not taken as a tool identifier.
        for name, cfg_data in iter_mcp_servers(data):
            origins.setdefault(name, cfg)
            args = cfg_data.get("args")
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str):
                        origins.setdefault(arg, cfg)
    return origins, parsed


def _discover_mcp_tools(project_root: Path) -> set[str]:
    """Collect tool/server identifiers from MCP config files."""
    return set(_mcp_tool_origins(project_root)[0])


# `\s*(?:\(\s*)?`, not `\s*\(?\s*`: with no `(`, the two `\s*` split a run of
# blanks every way, so a long line of them took the square of its length.
_TOOL_DECORATOR_RE = re.compile(
    r"""
    @(?:mcp\s*\.\s*tool|server\s*\.\s*tool|tool|langchain\s*\.\s*tools\s*\.\s*tool)
    \s*(?:\(\s*)?[\)\n]
    """,
    re.VERBOSE,
)
_DEF_NAME_RE = re.compile(r"def\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(")


def _discover_repo_tools(project_root: Path) -> set[str]:
    """Names of @tool / @mcp.tool decorated functions in the repo."""
    tools: set[str] = set()
    for path in project_root.rglob("*.py"):
        if in_skip_dir(path, project_root):
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

    origins, scanned = _mcp_tool_origins(project_root)
    discovered = set(origins) | _discover_repo_tools(project_root)
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
        # The config that declared the pair's first MCP tool, sources first.
        # A pair made only of `@tool` functions in the repo keeps the old
        # `.mcp.json` placeholder: those are not tracked to a file.
        report_path = next(
            (origins[t] for t in (*source_tools, *sink_tools) if t in origins),
            ".mcp.json",
        )
        findings.append(make_finding(
            "AAK-TOXICFLOW-001",
            report_path,
            evidence,
        ))
    return findings, scanned


def discovered_tools(project_root: Path) -> Iterable[str]:
    """Helper for `agent-audit-kit toxic-flow --explain` (future CLI)."""
    return sorted(_discover_mcp_tools(project_root) | _discover_repo_tools(project_root))
