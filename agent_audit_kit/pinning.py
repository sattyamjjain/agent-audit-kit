from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    iter_mcp_servers,
    loads_json,
    loads_jsonc,
    make_finding,
    read_text_capped,
)


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
            data = loads_jsonc(read_text_capped(config_path, CONFIG_MAX_BYTES, encoding=None, errors="replace"), config_path)
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

    The scanned repository can ship anything under `.agent-audit-kit`, and
    `Path.mkdir(exist_ok=True)` with `Path.write_text` took the pins through a
    link to a directory outside the project, over the target of a link at the pin
    file, and into a FIFO that blocked `aak pin` forever. The directory and the
    file now go through the checks `aak fix` writes with
    (`fix._make_dir_inside_project`, `fix._write_inside_project`).

    Args:
        project_root: The project root directory.

    Returns:
        The number of tools pinned.

    Raises:
        PinWriteError: the pin file, or the directory it goes in, is not one
            those checks allow, or could not be written; nothing was written.
    """
    # Imported here so the pin-drift scanner, which imports this module, does
    # not pull in fix.py and the scan engine it imports.
    from agent_audit_kit.fix import _as_written, _make_dir_inside_project, _write_inside_project

    tools = _discover_tools(project_root)
    pin_dir = project_root / ".agent-audit-kit"
    pins = {key: {"hash": t["hash"], "name": t["name"]} for key, t in tools.items()}
    refused = _make_dir_inside_project(pin_dir, project_root)
    if refused is None:
        text = _as_written(json.dumps(pins, indent=2))
        refused = _write_inside_project(pin_dir / "tool-pins.json", text, project_root)
    if refused is not None:
        raise PinWriteError(refused)
    return len(pins)


#: Where `create_pins` writes and `verify_pins` reads, relative to the project root.
PIN_FILE = ".agent-audit-kit/tool-pins.json"


class PinWriteError(OSError):
    """`create_pins` wrote no pin file; the message says why.

    The pin file or its directory is a link out of the project, a FIFO, or
    anything else `fix._write_refusal` and `fix._make_dir_inside_project`
    refuse, or the write failed. `pin` reports it on stderr and exits with an
    error, since no baseline was recorded; an OS error used to end in a
    traceback.
    """


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

    The file is read as AAK's other config files are, up to 1 MB
    (`read_text_capped`, whose refusal is an OSError), and parsed without the
    recursion that took the scan's pin-drift check down on a deeply nested
    file. A refusal of either kind is this error, with its reason; the parse
    names no path, so that `aak scan` reports it once, here, and not a second
    time as a refused file.
    """
    try:
        text = read_text_capped(pin_file, CONFIG_MAX_BYTES)
    except UnicodeDecodeError as exc:
        raise PinFileError(f"{PIN_FILE} is not UTF-8 text ({exc.reason} at byte {exc.start})") from exc
    except OSError as exc:
        raise PinFileError(f"{PIN_FILE} could not be read ({exc.strerror or exc})") from exc
    try:
        pins = loads_json(text, None)
    except (RecursionError, MemoryError) as exc:
        # The nesting screen's refusal says why ("JSON nested deeper than 500
        # levels"), as does a parser that still runs out of stack; MemoryError
        # says nothing, so its name stands in.
        raise PinFileError(f"{PIN_FILE} could not be read ({str(exc) or type(exc).__name__})") from exc
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
