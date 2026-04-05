from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


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
    "VS Code Copilot": [".vscode/mcp.json", ".github/copilot-instructions.md"],
    "Windsurf": [".windsurf/mcp.json", ".windsurfrules"],
    "Amazon Q": [".amazonq/mcp.json"],
    "Gemini CLI": [],  # user-level only
    "Goose": [".goose/config.yaml", ".goose/config.json"],
    "Continue": [".continue/config.json"],
    "Roo Code": [".roo/mcp.json", ".roo/rules"],
    "Kiro": [".kiro/mcp.json", ".kiro/rules"],
}

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
    """Count hook entries in a parsed JSON config.

    Hooks are expected under a top-level ``"hooks"`` key as a dict
    mapping event names to lists of hook definitions.

    Args:
        data: Parsed JSON data from a config file.

    Returns:
        Total number of hook entries found.
    """
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return 0
    count = 0
    for entries in hooks.values():
        if isinstance(entries, list):
            count += len(entries)
        else:
            count += 1
    return count


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

                    try:
                        data = json.loads(fp.read_text())
                    except (json.JSONDecodeError, OSError):
                        continue

                    # Count MCP servers from mcp config files
                    if "mcp" in fp.name.lower():
                        servers = data.get("mcpServers", {})
                        if isinstance(servers, dict):
                            agent.mcp_server_count += len(servers)

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
