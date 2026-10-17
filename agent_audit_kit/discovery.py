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
                    is_mcp_config = "mcp" in fp.name.lower()
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
