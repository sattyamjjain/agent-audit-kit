from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    ZCODE_WORKSPACE_CONFIG_NAMES,
    is_zcode_workspace_config,
    iter_hook_handlers,
    loads_json,
    loads_jsonc,
    mcp_server_maps,
    read_text_capped,
)


@dataclass
class DiscoveredAgent:
    """Represents an AI coding agent discovered on the filesystem.

    Attributes:
        name: Human-readable agent name (e.g. "Claude Code", "Cursor").
        config_files: Absolute paths to configuration files found.
        mcp_server_count: Number of MCP servers defined across configs.
        hook_count: Number of hooks defined across configs.
    """

    name: str
    config_files: list[str] = field(default_factory=list)
    mcp_server_count: int = 0
    hook_count: int = 0


AGENT_CONFIGS: dict[str, list[str]] = {
    "Claude Code": [
        ".mcp.json",
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude/CLAUDE.md",
    ],
    "Cursor": [".cursor/mcp.json", ".cursorrules"],
    "VS Code Copilot": [
        ".vscode/mcp.json",
        ".github/copilot-instructions.md",
        ".vscode/tasks.json",
        ".vscode/launch.json",
    ],
    "Windsurf": [".windsurf/mcp.json", ".windsurfrules"],
    "Amazon Q": [".amazonq/mcp.json"],
    "Gemini CLI": [],  # user-level only
    "Goose": [".goose/config.yaml", ".goose/config.json"],
    "Continue": [".continue/config.json"],
    "Roo Code": [".roo/mcp.json", ".roo/rules"],
    "Kiro": [".kiro/mcp.json", ".kiro/rules"],
    "ZCode": list(ZCODE_WORKSPACE_CONFIG_NAMES),
}

# AGENT_CONFIGS entries that hold a server map without being named `mcp.json`.
# Continue's is read as one by mcp_config and mcp_sampling_capability. Goose's
# `.goose/config.json` is not: no scanner parses it, and Goose keeps its servers
# as `extensions` in YAML.
_SERVER_MAP_CONFIGS_NOT_NAMED_MCP = frozenset({".continue/config.json"})

#: The project-relative paths of the files that hold an MCP server map
#: (`mcpServers`, or VS Code's `servers`), in AGENT_CONFIGS order, then the root
#: `mcp.json`. Every scanner that reads "the MCP configs" at the project root
#: reads this tuple, so a server is judged the same wherever it is declared and a
#: new client location is added here once.
#:
#: `.claude/mcp.json` is deliberately absent: Claude Code's MCP documentation
#: names `.mcp.json` at the project root as the project-scoped config, and no
#: client loads `.claude/mcp.json`. The scanners that glob `*mcp*.json` still
#: read it, as they read any such file below the root.
MCP_SERVER_CONFIGS: tuple[str, ...] = tuple(dict.fromkeys(
    [
        path
        for paths in AGENT_CONFIGS.values()
        for path in paths
        if path.endswith("mcp.json") or path in _SERVER_MAP_CONFIGS_NOT_NAMED_MCP
    ]
    + ["mcp.json"]
))

_MCP_SERVER_CONFIG_SET = frozenset(MCP_SERVER_CONFIGS)
_MCP_SERVER_CONFIG_NAMES = frozenset(path.rsplit("/", 1)[-1] for path in MCP_SERVER_CONFIGS)


def is_mcp_server_config(path: Path, project_root: Path) -> bool:
    """Whether `path` is one of `MCP_SERVER_CONFIGS` of the project at `project_root`.

    Matched by the path below the root, in POSIX form, never by the file name:
    `.cursor/settings.json` is not one, and neither is `sub/.cursor/mcp.json`,
    a nested project's config, which the root-anchored readers have never read
    (the scanners that glob `*mcp*.json` read it as any other such file). A path
    outside `project_root` is not one. The name is compared first, so a walk
    that asks this of every file pays a set lookup for most of them.

    Args:
        path: The file, absolute or relative to the working directory.
        project_root: The root of the project being scanned.

    Returns:
        True when the path below `project_root` is listed in `MCP_SERVER_CONFIGS`.
    """
    if path.name not in _MCP_SERVER_CONFIG_NAMES:
        return False
    try:
        rel = path.relative_to(project_root)
    except ValueError:
        return False
    return rel.as_posix() in _MCP_SERVER_CONFIG_SET


USER_AGENT_CONFIGS: dict[str, list[str]] = {
    "Claude Code (user)": ["~/.claude.json", "~/.claude/settings.json"],
    "Gemini CLI (user)": ["~/.gemini/settings.json"],
    "Goose (user)": ["~/.config/goose/config.yaml"],
    "Continue (user)": ["~/.continue/config.json"],
}

# Config files known to contain hooks (keyed by agent name).
_HOOK_CONFIGS: dict[str, set[str]] = {
    "Claude Code": {".claude/settings.json", ".claude/settings.local.json"},
}


def _count_hooks(data: dict) -> int:
    """Count the hooks in a parsed JSON config.

    Hooks are expected under a top-level ``"hooks"`` key as a dict mapping
    event names to lists of entries. Claude Code documents each entry as a
    matcher group whose own ``hooks`` array holds the handlers, so the count is
    of handlers, the same count AAK-HOOK-007 uses; counting entries reported a
    group of twelve hooks as one.

    Args:
        data: Parsed JSON data from a config file.

    Returns:
        Total number of hooks found.
    """
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return 0
    return sum(1 for _ in iter_hook_handlers(hooks))


def discover_agents(
    project_root: Path | None = None,
    verbose: bool = False,
) -> list[DiscoveredAgent]:
    """Discover AI coding agents configured in a project or user home.

    Scans for known configuration file patterns associated with popular
    AI coding agents. For project-level configs, also counts MCP servers
    and hooks found in JSON config files.

    Args:
        project_root: Path to the project directory. If None, only
            user-level configs are checked.
        verbose: Reserved for future use (debug output).

    Returns:
        A list of DiscoveredAgent instances for each agent whose
        configuration files were found.
    """
    agents: list[DiscoveredAgent] = []

    # Project-level discovery
    if project_root:
        for name, paths in AGENT_CONFIGS.items():
            found: list[str] = []
            for p in paths:
                full = project_root / p
                if full.exists():
                    found.append(str(full))
            if found:
                agent = DiscoveredAgent(name=name, config_files=found)
                hook_config_names = _HOOK_CONFIGS.get(name, set())

                for f in found:
                    fp = Path(f)
                    if fp.suffix != ".json":
                        continue

                    # An MCP config is read the way VS Code reads
                    # `.vscode/mcp.json`, comments and trailing commas allowed.
                    # Claude Code's settings files stay strict JSON: Claude Code
                    # rejects a comment or a trailing comma in them, and skips
                    # the file, hooks included. So does ZCode, whose workspace
                    # files hold MCP servers under names without "mcp" in them.
                    zcode = is_zcode_workspace_config(fp)
                    # Continue's `.continue/config.json` holds a server map
                    # without "mcp" in its name; it was counted as none.
                    is_mcp_config = "mcp" in fp.name.lower() or is_mcp_server_config(fp, project_root)
                    try:
                        text = read_text_capped(fp, CONFIG_MAX_BYTES, encoding=None, errors="replace")
                        data = loads_jsonc(text, fp) if is_mcp_config else loads_json(text, fp)
                    except (json.JSONDecodeError, OSError):
                        continue

                    # Count MCP servers from mcp config files, under either key:
                    # VS Code's `.vscode/mcp.json` uses `servers`, so reading
                    # only `mcpServers` reported every VS Code workspace as 0.
                    if is_mcp_config or zcode:
                        agent.mcp_server_count += sum(
                            len(servers) for _, servers in mcp_server_maps(data, fp)
                        )

                    # Count hooks from known hook config files
                    rel_path = str(fp.relative_to(project_root))
                    if rel_path in hook_config_names:
                        agent.hook_count += _count_hooks(data)

                agents.append(agent)

    # User-level discovery
    for name, paths in USER_AGENT_CONFIGS.items():
        found = []
        for p in paths:
            full = Path(p).expanduser()
            if full.exists():
                found.append(str(full))
        if found:
            agents.append(DiscoveredAgent(name=name, config_files=found))

    return agents
