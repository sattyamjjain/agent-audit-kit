"""SHA-256 pins of MCP tool definitions and server launches, behind `aak pin` and `aak verify`.

`write_pins` writes `PIN_FILE` (`create_pins` is the same, returning the tool
count alone); `verify_pins` compares the project's MCP configs with it and
reports AAK-RUGPULL-001 (changed), -002 (added) and -003 (removed). The
pin-drift scanner and `aak watch` call `verify_pins` too.

Pin format v2
-------------
Every entry `write_pins` writes carries ``"v": 2`` and a ``"kind"``:

- ``"<server>/<tool>"``, kind ``"tool"``: the hash covers the tool's ``name``,
  ``description``, ``inputSchema``, ``annotations``, ``title`` and
  ``outputSchema``, each ``json.dumps(..., sort_keys=True)``, ``""`` when the
  tool has no such key.
- ``"<server>/"``, kind ``"server"``: the hash covers the server's launch,
  ``command``, ``args``, ``url`` and ``type`` the same way, and the sorted
  names of its ``env`` keys. Every server gets one, with or without a
  ``tools`` list.

The first format hashed a tool's name, description and input schema and
nothing else. Flipping ``readOnlyHint`` to false, retitling ``read_file``
"Delete anything", adding an ``exfil`` property to its output schema and
swapping the server's ``npx`` launch for ``bash -c "curl ... | sh"`` left
`aak verify` printing that every tool matched its pin.

Why the launch is not part of the tool hash: a changed command would then be
reported once for every tool the server declares and once more for the server,
where one change should be one AAK-RUGPULL-001. So the launch lives in the
``"<server>/"`` entry alone, the entry that also gives a server declaring no
tools (they arrive at run time through ``tools/list``) a baseline at all. A
tool whose name is empty or ends in ``/`` is not pinned, since its key would
read as a server's.

Env values never enter a hash, the pin file or a finding's evidence: they are
where tokens live, and the pin file is committed. Only the key names are pinned,
so an added or removed variable changes the launch and a rotated token does not.

Pin files written before v2
---------------------------
An entry without ``"v"`` is compared with the hash it was written with,
`_hash_tool` over name, description and input schema, so upgrading does not
report every pinned tool as changed. Such a file pins no server either, so
while the pin file holds one, a server missing from it is not reported as
added; `predates_v2` lets `aak verify` and the pin-drift scanner print
`PIN_V1_NOTE` on stderr instead, until `aak pin` writes the file again. A pin
map with no entries holds none from before v2, so every current server is new
to it, as every current tool is.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, NamedTuple

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    iter_mcp_servers,
    loads_json,
    loads_jsonc,
    make_finding,
    read_text_capped,
)

#: The pin format `write_pins` writes. An entry without ``"v"`` predates it.
PIN_VERSION = 2

#: Printed once on stderr by `aak verify` and by the pin-drift scanner when the
#: pin file holds an entry without ``"v"``.
PIN_V1_NOTE = (
    "pin file predates v2; run aak pin to also cover annotations, title, outputSchema and server launch"
)

#: The tool keys a v2 tool hash covers, in hash order.
TOOL_FIELDS = ("name", "description", "inputSchema", "annotations", "title", "outputSchema")

#: The server keys a launch hash covers, in hash order; the sorted names of the
#: ``env`` keys follow them.
LAUNCH_FIELDS = ("command", "args", "url", "type")

_CONFIG_NAMES = (
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
)


def _hash_tool(name: str, description: str, input_schema: str) -> str:
    """The hash of a pin entry without ``"v"``: name, description and input schema.

    Kept so that a pin file written before v2 is compared with what it recorded.

    Args:
        name: Tool name.
        description: Tool description.
        input_schema: JSON-serialized input schema string.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    content = f"{name}:{description}:{input_schema}"
    return hashlib.sha256(content.encode()).hexdigest()


def _field(holder: dict[str, Any], key: str) -> str:
    """``holder[key]`` as sorted-key JSON, or ``""`` when ``holder`` has no ``key``."""
    return json.dumps(holder[key], sort_keys=True) if key in holder else ""


def _digest(kind: str, parts: list[str]) -> str:
    """SHA-256 of ``kind`` and ``parts`` written as one JSON array.

    The array keeps the parts apart, so no value can pass for its neighbour by
    containing a separator, and ``kind`` keeps a tool hash and a launch hash
    from ever being the same.
    """
    return hashlib.sha256(json.dumps([kind, *parts]).encode()).hexdigest()


def _hash_tool_v2(tool: dict[str, Any]) -> str:
    """The v2 hash of a tool: every key in `TOOL_FIELDS`."""
    return _digest("tool", [_field(tool, key) for key in TOOL_FIELDS])


def _hash_launch(server: dict[str, Any]) -> str:
    """The v2 hash of a server's launch: `LAUNCH_FIELDS` and its env key names.

    The values under ``env`` are never read. An ``env`` that is not an object
    contributes no names, as an absent one does; a client launches neither with
    variables from it.
    """
    env = server.get("env")
    env_names = sorted(str(name) for name in env) if isinstance(env, dict) else []
    return _digest("server", [_field(server, key) for key in LAUNCH_FIELDS] + [json.dumps(env_names)])


def _discover(project_root: Path) -> dict[str, dict[str, Any]]:
    """Every server and tool the project's MCP configs declare, keyed as the pin file keys them.

    Reads the known MCP config locations (`_CONFIG_NAMES`), each server under
    ``mcpServers`` or VS Code's ``servers``, in config order: a server's
    ``"<server>/"`` entry, then one ``"<server>/<tool>"`` entry per tool in its
    ``tools`` list. A server entry holds ``kind``, ``name`` and ``hash`` (the
    launch). A tool entry holds ``kind``, ``name``, ``description``,
    ``inputSchema`` (the JSON string the first format hashed), ``hash`` (that
    first format's hash, `_hash_tool`) and ``hash_v2`` (`_hash_tool_v2`), so a
    pin of either format can be compared.

    A tool whose name is empty or ends in ``/`` is skipped: its key would end
    in ``/`` and stand for a server, and one entry would replace the other.

    Args:
        project_root: The project root directory to search in.

    Returns:
        The entries, in the order above.
    """
    current: dict[str, dict[str, Any]] = {}
    for config_name in _CONFIG_NAMES:
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
            current[f"{server_name}/"] = {"kind": "server", "name": server_name, "hash": _hash_launch(server_cfg)}
            server_tools = server_cfg.get("tools", [])
            if not isinstance(server_tools, list):
                continue
            for tool in server_tools:
                if not isinstance(tool, dict) or "name" not in tool:
                    continue
                key = f"{server_name}/{tool['name']}"
                if key.endswith("/"):
                    continue
                schema_str = json.dumps(tool.get("inputSchema", {}), sort_keys=True)
                current[key] = {
                    "kind": "tool",
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "inputSchema": schema_str,
                    "hash": _hash_tool(tool.get("name", ""), tool.get("description", ""), schema_str),
                    "hash_v2": _hash_tool_v2(tool),
                }
    return current


def _discover_tools(project_root: Path) -> dict[str, dict]:
    """The tool entries of `_discover`, keyed ``server/tool``.

    Args:
        project_root: The project root directory to search in.

    Returns:
        A dict mapping ``server_name/tool_name`` keys to dicts containing
        name, description, inputSchema, hash (first format) and hash_v2.
    """
    return {key: entry for key, entry in _discover(project_root).items() if entry["kind"] == "tool"}


class PinCounts(NamedTuple):
    """What `write_pins` recorded: tool definitions and server launches."""

    tools: int
    servers: int


def write_pins(project_root: Path) -> PinCounts:
    """Pin every tool and every server launch the project's MCP configs declare.

    Writes `PIN_FILE` in the v2 format (see the module docstring): one entry per
    tool and one ``"<server>/"`` entry per server, each with ``"v": 2``, its
    ``kind``, its ``name`` and its ``hash``.

    The scanned repository can ship anything under `.agent-audit-kit`, and
    `Path.mkdir(exist_ok=True)` with `Path.write_text` took the pins through a
    link to a directory outside the project, over the target of a link at the pin
    file, and into a FIFO that blocked `aak pin` forever. The directory and the
    file now go through the checks `aak fix` writes with
    (`fix._make_dir_inside_project`, `fix._write_inside_project`).

    Args:
        project_root: The project root directory.

    Returns:
        How many tools and how many servers were pinned.

    Raises:
        PinWriteError: the pin file, or the directory it goes in, is not one
            those checks allow, or could not be written; nothing was written.
    """
    # Imported here so the pin-drift scanner, which imports this module, does
    # not pull in fix.py and the scan engine it imports.
    from agent_audit_kit.fix import _as_written, _make_dir_inside_project, _write_inside_project

    pins = {
        key: {
            "v": PIN_VERSION,
            "kind": entry["kind"],
            "name": entry["name"],
            "hash": entry["hash_v2"] if entry["kind"] == "tool" else entry["hash"],
        }
        for key, entry in _discover(project_root).items()
    }
    pin_dir = project_root / ".agent-audit-kit"
    refused = _make_dir_inside_project(pin_dir, project_root)
    if refused is None:
        text = _as_written(json.dumps(pins, indent=2))
        refused = _write_inside_project(pin_dir / "tool-pins.json", text, project_root)
    if refused is not None:
        raise PinWriteError(refused)
    servers = sum(1 for pin in pins.values() if pin["kind"] == "server")
    return PinCounts(tools=len(pins) - servers, servers=servers)


def create_pins(project_root: Path) -> int:
    """`write_pins`, returning the number of tools pinned.

    Args:
        project_root: The project root directory.

    Returns:
        The number of tools pinned. Servers are pinned too, and not counted.

    Raises:
        PinWriteError: as `write_pins`.
    """
    return write_pins(project_root).tools


#: Where `write_pins` writes and `verify_pins` reads, relative to the project root.
PIN_FILE = ".agent-audit-kit/tool-pins.json"


class PinWriteError(OSError):
    """`write_pins` (or `create_pins`) wrote no pin file; the message says why.

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


def _shown(value: object) -> str:
    """``value`` for an error message: a short scalar as written, anything else by its JSON type.

    A hostile pin file can put a megabyte under ``v``, and the message becomes
    a finding's evidence.
    """
    if value is None or isinstance(value, bool) or (isinstance(value, (int, float)) and abs(value) < 10**9):
        return json.dumps(value)
    if isinstance(value, str) and len(value) <= 40:
        return json.dumps(value)
    return f"a JSON {_JSON_TYPE_NAMES.get(type(value), 'object')}"


def _load_pins(pin_file: Path) -> dict[str, dict[str, Any]]:
    """The pins in ``pin_file``, or `PinFileError` when it cannot be used.

    Beyond parsing, the shape is checked: the top level must be an object and
    every entry an object with a string ``hash``, the one field the comparison
    reads. A JSON array or an entry without a hash used to raise from inside the
    comparison (``AttributeError``, ``KeyError``), which reached the user as a
    scanner crash with no hint that the pin file was the cause.

    An entry may carry ``v`` and ``kind`` (the module docstring has the format).
    ``v`` is 2 or absent, absent meaning a pin from before v2; a ``v`` this
    release does not know is refused rather than compared with a hash it was
    never written with, which would report every pin as changed. ``kind`` is
    ``"tool"``, ``"server"`` or absent, absent meaning a tool.

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
        version = entry.get("v", PIN_VERSION)
        if type(version) is not int or version != PIN_VERSION:
            raise PinFileError(
                f"{PIN_FILE} entry {key!r} has `v` {_shown(version)}; this release reads "
                f"{PIN_VERSION} and entries without `v`"
            )
        if entry.get("kind", "tool") not in ("tool", "server"):
            raise PinFileError(
                f"{PIN_FILE} entry {key!r} has `kind` {_shown(entry['kind'])}, not \"tool\" or \"server\""
            )
    return pins


def _holds_v1_entry(pins: dict[str, dict[str, Any]]) -> bool:
    """Whether any entry of ``pins`` was written before v2, without ``v``."""
    return any("v" not in entry for entry in pins.values())


def predates_v2(project_root: Path) -> bool:
    """Whether the pin file holds an entry written before v2, for `PIN_V1_NOTE`.

    `verify_pins` keeps its one-argument signature (`aak watch` calls it, and
    tests stand in for it with one-argument functions), so a caller asks this
    after it returns, and the pin file is read a second time, capped as the
    first read is. A file that cannot be read here either made `verify_pins`
    raise already or changed in between; the verdict already reported stands
    and there is no note to add, so the answer is False.

    Args:
        project_root: The project root directory.

    Returns:
        True when the pin file exists, reads, and holds an entry without ``v``.
    """
    pin_file = project_root / PIN_FILE
    if not pin_file.is_file():
        return False
    try:
        return _holds_v1_entry(_load_pins(pin_file))
    except PinFileError:
        return False


def verify_pins(project_root: Path) -> list[Finding]:
    """Verify current tool definitions and server launches against their pins.

    Compares the MCP configs with ``.agent-audit-kit/tool-pins.json``:

    - AAK-RUGPULL-001: a pinned tool's hash differs (the v2 hash for a v2
      entry, the first format's for an entry without ``v``), or a pinned
      server's launch hash differs ("Server '<name>' launch changed since last
      pin").
    - AAK-RUGPULL-002: a tool is not in the pin file, or a server is not and
      the pin file holds no entry from before v2. Such a file pins no server,
      so a server missing from it says nothing; `predates_v2` covers that case.
    - AAK-RUGPULL-003: a pinned tool, or a pinned server, is gone.

    Each differing key is one finding, so a server added with two tools is
    three AAK-RUGPULL-002 findings: its launch and each tool are new.

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
    servers_pinned = not _holds_v1_entry(old_pins)

    current = _discover(project_root)
    findings: list[Finding] = []

    def report(rule_id: str, evidence: str) -> None:
        findings.append(make_finding(rule_id, PIN_FILE, evidence))

    for key, old in old_pins.items():
        now = current.get(key)
        if old.get("kind") == "server":
            name = key[:-1] if key.endswith("/") else key
            if now is None or now["kind"] != "server":
                report("AAK-RUGPULL-003", f"Server '{name}' was removed since last pin")
            elif now["hash"] != old["hash"]:
                report("AAK-RUGPULL-001", f"Server '{name}' launch changed since last pin")
        elif now is None or now["kind"] != "tool":
            report("AAK-RUGPULL-003", f"Tool '{key}' was removed since last pin")
        elif (now["hash_v2"] if "v" in old else now["hash"]) != old["hash"]:
            report("AAK-RUGPULL-001", f"Tool '{key}' definition changed since last pin")

    for key, now in current.items():
        if key in old_pins:
            continue
        if now["kind"] == "tool":
            report("AAK-RUGPULL-002", f"New tool '{key}' added since last pin")
        elif servers_pinned:
            report("AAK-RUGPULL-002", f"New server '{key[:-1]}' added since last pin")

    return findings
