from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import iter_mcp_servers, loads_jsonc, make_finding


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

    Scans known MCP config locations for tool definitions (under
    ``mcpServers`` or VS Code's ``servers``) and computes a SHA-256 hash
    for each tool based on its name, description, and input schema.

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
            data = loads_jsonc(config_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        # `mcpServers`, and the `servers` map of VS Code's `.vscode/mcp.json`.
        # That file was on the list while only `mcpServers` was read, so `pin`
        # recorded none of its tools and a rug pull there was never reported.
        for server_name, server_cfg in iter_mcp_servers(data):
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


#: Where `create_pins` writes and `verify_pins` reads, relative to the project root.
PIN_FILE = ".agent-audit-kit/tool-pins.json"


class PinFileError(ValueError):
    """The pin file exists but cannot serve as the baseline `verify_pins` compares against.

    `verify_pins` used to return ``[]`` here, which is also its answer for
    "every tool matches its pin". So a trailing comma left by a hand edit, a
    merge conflict or a truncated write turned AAK-RUGPULL-001, -002 and -003
    off without a word: `aak scan` passed, `aak verify` printed that all tool
    definitions matched their pins, and `aak watch` printed "clean". A rug-pull
    check that cannot read its baseline has checked nothing, so this is raised
    instead and every caller reports it in its own terms: the pin-drift
    scanner marks the scan incomplete, `verify` exits with an error, and
    `watch` prints "not verified".

    Attributes:
        line: 1-based line of the JSON syntax error, or ``None`` when the
            problem is not a syntax error.
    """

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


_JSON_TYPE_NAMES: dict[type, str] = {
    list: "array",
    str: "string",
    int: "number",
    float: "number",
    bool: "boolean",
    type(None): "null",
}


def _load_pins(pin_file: Path) -> dict[str, dict[str, Any]]:
    """The pins in ``pin_file``, or `PinFileError` when it cannot be used.

    Beyond parsing, the shape is checked: the top level must be an object and
    every entry an object with a string ``hash``, the one field the comparison
    reads. A JSON array or an entry without a hash used to raise from inside the
    comparison (``AttributeError``, ``KeyError``), which reached the user as a
    scanner crash with no hint that the pin file was the cause.
    """
    try:
        text = pin_file.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PinFileError(f"{PIN_FILE} is not UTF-8 text ({exc.reason} at byte {exc.start})") from exc
    except OSError as exc:
        raise PinFileError(f"{PIN_FILE} could not be read ({exc.strerror or exc})") from exc
    try:
        pins = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PinFileError(
            f"{PIN_FILE} is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})",
            line=exc.lineno,
        ) from exc
    if not isinstance(pins, dict):
        kind = _JSON_TYPE_NAMES.get(type(pins), type(pins).__name__)
        raise PinFileError(f"{PIN_FILE} holds a JSON {kind}, not an object of server/tool pins")
    for key, entry in pins.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("hash"), str):
            raise PinFileError(f"{PIN_FILE} entry {key!r} has no string `hash`")
    return pins


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

    Raises:
        PinFileError: the pin file exists but cannot be read, is not valid
            JSON, or is not a map of pins. Nothing was compared, so an empty
            list would claim a match that was never checked.
    """
    pin_file = project_root / PIN_FILE
    if not pin_file.is_file():
        return []
    old_pins = _load_pins(pin_file)

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
