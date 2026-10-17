"""AAK-TOXICFLOW-001 — toxic-flow source/sink pair scoring.

Snyk Agent Scan parity. Discover the tools the agent project exposes
(MCP server names and args in `.mcp.json` and the other MCP config
files, VS Code's `servers` object included, + `@tool`-decorated Python
functions in the repo) and emit a HIGH finding for every
(sensitive_source, external_sink) pair listed in
`agent_audit_kit/data/toxic_flow_pairs.yml` — unless the pair appears
in `.aak-toxic-flow-trust.yml` with a non-empty justification. Skills
are not read; the rule's limitation text lists what else is not.

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

from ._helpers import (
    CONFIG_MAX_BYTES,
    SOURCE_MAX_BYTES,
    in_skip_dir,
    iter_mcp_servers,
    load_yaml,
    loads_jsonc,
    make_finding,
    read_text_capped,
)


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_PAIRS_PATH = _DATA_DIR / "toxic_flow_pairs.yml"


def _load_pairs() -> dict:
    if not _PAIRS_PATH.is_file():
        return {"sources": {}, "sinks": {}, "pairs": []}
    try:
        return load_yaml(_PAIRS_PATH.read_text(encoding="utf-8"), _PAIRS_PATH) or {}
    except yaml.YAMLError:
        return {"sources": {}, "sinks": {}, "pairs": []}


def _flag_enabled() -> bool:
    return os.environ.get("AAK_TOXIC_FLOW", "").strip() not in ("", "0", "false", "False")


def _load_trust(project_root: Path) -> set[tuple[str, str]]:
    trust_path = project_root / ".aak-toxic-flow-trust.yml"
    if not trust_path.is_file():
        return set()
    try:
        data = load_yaml(read_text_capped(trust_path, CONFIG_MAX_BYTES, errors="replace"), trust_path) or {}
    except (yaml.YAMLError, OSError):
        return set()
    if not isinstance(data, dict):
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
            data = loads_jsonc(read_text_capped(p, CONFIG_MAX_BYTES, errors="replace"), p)
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
# The second arm is the bare decorator, `@tool` with nothing after it but
# blanks or a comment, which is the form LangChain documents. The first arm
# alone never saw it: it wants `)` or a newline after the name, and the lines
# come from `splitlines()`, which drops the newline. The `$` arm cannot follow
# a `(`, so a call whose arguments sit on the next lines (`@tool(`) stays out.
# A decorator starts its line: unanchored, the `$` arm read a comment that ends
# in `@tool` ("the public ones are wrapped with @tool") as one, and made the
# undecorated `def` below it a tool.
_TOOL_DECORATOR_RE = re.compile(
    r"""
    ^\s*@(?:mcp\s*\.\s*tool|server\s*\.\s*tool|tool|langchain\s*\.\s*tools\s*\.\s*tool)
    (?:\s*(?:\(\s*)?[\)\n]|\s*(?:\#[^\n]*)?$)
    """,
    re.VERBOSE,
)
_DEF_NAME_RE = re.compile(r"def\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(")


def _repo_tool_origins(project_root: Path) -> dict[str, tuple[str, int]]:
    """Names of @tool / @mcp.tool decorated functions in the repo, with where each is.

    Maps a name to the file (relative to ``project_root``) and the line of the
    first ``def`` that declared it, in path order, so a pair made only of
    these functions is reported where its first tool is written instead of
    against a `.mcp.json` the project may not have. The walk is sorted: in
    directory order a name declared in two files could point at either.
    """
    origins: dict[str, tuple[str, int]] = {}
    for path in sorted(project_root.rglob("*.py")):
        if in_skip_dir(path, project_root):
            continue
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        if "@tool" not in text and "@mcp.tool" not in text and "@server.tool" not in text:
            continue
        rel = str(path.relative_to(project_root))
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
                        origins.setdefault(m.group(1), (rel, i + off + 1))
                        break
    return origins


def _discover_repo_tools(project_root: Path) -> set[str]:
    """Names of @tool / @mcp.tool decorated functions in the repo."""
    return set(_repo_tool_origins(project_root))


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
    repo_origins = _repo_tool_origins(project_root)
    # A file that declared a tool was read for the graph, like a config.
    scanned |= {rel for rel, _ in repo_origins.values()}
    discovered = set(origins) | set(repo_origins)
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
        # A pair made only of `@tool` functions in the repo has no config: it
        # is reported at the `def` of its first tool, which used to be the
        # `.mcp.json` placeholder whether or not the project had one. Every
        # discovered tool has one origin or the other.
        pair = (*source_tools, *sink_tools)
        report_path = next((origins[t] for t in pair if t in origins), None)
        line: int | None = None
        if report_path is None:
            report_path, line = repo_origins[pair[0]]
        findings.append(make_finding(
            "AAK-TOXICFLOW-001",
            report_path,
            evidence,
            line,
        ))
    return findings, scanned


def discovered_tools(project_root: Path) -> Iterable[str]:
    """Every tool identifier the rule pairs, sorted: MCP server names and args, and repo functions.

    No CLI command calls it; the finding's evidence names the tools of each pair.
    """
    return sorted(_discover_mcp_tools(project_root) | _discover_repo_tools(project_root))
