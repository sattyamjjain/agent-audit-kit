from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding


def _hash_tool(name: str, description: str, input_schema: str) -> str:
    """Compute a SHA-256 hash of a tool's identity fields.

    Args:
        name: Tool name.
        description: Tool description.
        input_schema: JSON-serialized input schema string.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    content = f"{name}:{description}:{input_schema}"
    return hashlib.sha256(content.encode()).hexdigest()


def _discover_tools(project_root: Path) -> dict[str, dict]:
    """Find tool definitions from MCP configuration files.

    Scans known MCP config locations for tool definitions and computes
    a SHA-256 hash for each tool based on its name, description, and
    input schema.

    Args:
        project_root: The project root directory to search in.

    Returns:
        A dict mapping ``server_name/tool_name`` keys to dicts
        containing name, description, inputSchema, and hash.
    """
    tools: dict[str, dict] = {}
    config_names = [
        ".mcp.json",
        "mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".amazonq/mcp.json",
        ".windsurf/mcp.json",
        ".kiro/mcp.json",
        ".roo/mcp.json",
        ".continue/config.json",
        ".goose/config.json",
    ]

    for config_name in config_names:
        config_path = project_root / config_name
        if not config_path.is_file():
            continue
        try:
            data = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        servers = data.get("mcpServers", {})
        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            server_tools = server_cfg.get("tools", [])
            if isinstance(server_tools, list):
                for tool in server_tools:
                    if isinstance(tool, dict) and "name" in tool:
                        schema_str = json.dumps(
                            tool.get("inputSchema", {}), sort_keys=True
                        )
                        key = f"{server_name}/{tool['name']}"
                        tools[key] = {
                            "name": tool.get("name", ""),
                            "description": tool.get("description", ""),
                            "inputSchema": schema_str,
                            "hash": _hash_tool(
                                tool.get("name", ""),
                                tool.get("description", ""),
                                schema_str,
                            ),
                        }
    return tools


def create_pins(project_root: Path) -> int:
    """Create SHA-256 pins for all discovered MCP tools.

    Writes a ``tool-pins.json`` file under ``.agent-audit-kit/`` in
    the project root. Each pin records the tool's name and its hash.

    Args:
        project_root: The project root directory.

    Returns:
        The number of tools pinned.
    """
    tools = _discover_tools(project_root)
    pin_dir = project_root / ".agent-audit-kit"
    pin_dir.mkdir(exist_ok=True)
    pin_file = pin_dir / "tool-pins.json"
    pins = {key: {"hash": t["hash"], "name": t["name"]} for key, t in tools.items()}
    pin_file.write_text(json.dumps(pins, indent=2))
    return len(pins)


def verify_pins(project_root: Path) -> list[Finding]:
    """Verify current tool definitions against previously pinned hashes.

    Compares the current state of MCP tool definitions against the
    stored pins in ``.agent-audit-kit/tool-pins.json``. Generates
    findings for tools that were removed, changed, or newly added.

    Args:
        project_root: The project root directory.

    Returns:
        A list of Finding objects for any pin mismatches. Returns an
        empty list if no pin file exists or no changes are detected.
    """
    pin_file = project_root / ".agent-audit-kit" / "tool-pins.json"
    if not pin_file.is_file():
        return []
    try:
        old_pins = json.loads(pin_file.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    current_tools = _discover_tools(project_root)
    findings: list[Finding] = []

    for key, old in old_pins.items():
        if key not in current_tools:
            findings.append(
                make_finding(
                    "AAK-RUGPULL-003",
                    ".agent-audit-kit/tool-pins.json",
                    f"Tool '{key}' was removed since last pin",
                )
            )
        elif current_tools[key]["hash"] != old["hash"]:
            findings.append(
                make_finding(
                    "AAK-RUGPULL-001",
                    ".agent-audit-kit/tool-pins.json",
                    f"Tool '{key}' definition changed since last pin",
                )
            )

    for key in current_tools:
        if key not in old_pins:
            findings.append(
                make_finding(
                    "AAK-RUGPULL-002",
                    ".agent-audit-kit/tool-pins.json",
                    f"New tool '{key}' added since last pin",
                )
            )

    return findings
