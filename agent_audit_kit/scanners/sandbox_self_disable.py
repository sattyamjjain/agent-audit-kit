"""Sandbox/isolation self-disable parameter scanner — CVE-2026-42074 class.

Detects tool/function JSON schemas (and MCP tool descriptors) that expose a
parameter whose *name* disables or weakens sandboxing/isolation inside the
schema's ``properties`` — i.e. a flag the LLM (an untrusted principal) can set
in a ``tool_use`` response to turn off the sandbox that contains tool
execution.

This is the **CVE-2026-42074** class: OpenClaude < 0.5.1 exposed
``dangerouslyDisableSandbox`` as part of the BashTool input schema, so the
model could set it to ``true`` in any tool call (CWE-284 / CWE-306, CVSS 9.8).

Scope: this is a JSON-schema / descriptor scan, not an AST analyzer. It walks
JSON-Schema ``properties`` (the model-facing parameter surface) under the
standard tool-schema container keys — ``inputSchema`` (MCP), ``input_schema``
(Anthropic tools), ``parameters`` (OpenAI function-calling) — plus bare schema
files whose top-level object carries ``properties``. A property is treated as
NOT LLM-settable (and therefore not flagged) when it is annotated
``readOnly: true``, ``"x-aak-sandbox-control": "ops-only"`` (or
``operator-only`` / ``server-only``), or ``"x-llm-settable": false``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-SANDBOX-SELFDISABLE-001"

# Parameter names that disable or weaken sandboxing/isolation. Matched against
# the property *key* (case-insensitive); camelCase such as
# ``dangerouslyDisableSandbox`` is covered because the lowercased key contains
# ``dangerouslydisable``.
_DANGEROUS_PARAM_RE = re.compile(
    r"dangerous(?:ly)?[_-]?disable"
    r"|disable[_-]?sandbox"
    r"|no[_-]?sandbox"
    r"|allow[_-]?unsafe"
    r"|skip[_-]?isolation",
    re.IGNORECASE,
)

# JSON-Schema containers that hold a tool's model-facing parameter definitions.
_SCHEMA_KEYS: tuple[str, ...] = ("inputSchema", "input_schema", "parameters")

# Cheap raw-text pre-filter so we only json.loads files that could plausibly
# carry a tool/function schema (keeps the rglob bounded on large repos).
_MARKERS: tuple[str, ...] = (
    '"inputSchema"', '"input_schema"', '"parameters"',
    '"properties"', '"type": "function"', '"type":"function"',
)

# Depth caps: one for descending arbitrary JSON to find schema containers,
# one for walking nested object/array parameter schemas.
_MAX_DOC_DEPTH = 12
_MAX_PARAM_DEPTH = 8


def _is_ops_only(prop_schema: dict[str, Any]) -> bool:
    """Return True if the property is annotated as NOT settable by the model.

    Honoured signals:
      - JSON-Schema ``readOnly: true`` (host-set, not request-set)
      - ``"x-aak-sandbox-control": "ops-only"|"operator-only"|"server-only"``
      - ``"x-llm-settable": false``
    """
    if prop_schema.get("readOnly") is True:
        return True
    if prop_schema.get("x-llm-settable") is False:
        return True
    marker = prop_schema.get("x-aak-sandbox-control")
    if isinstance(marker, str) and marker.strip().lower() in (
        "ops-only", "operator-only", "server-only",
    ):
        return True
    return False


def _walk_schema_props(
    schema: Any,
    path: str,
    depth: int,
    out: list[tuple[str, str, bool]],
) -> None:
    """Collect (param_path, matched_name, ops_only) for dangerous param names.

    Descends ``properties`` (object params), ``items`` (array element schemas),
    and the ``anyOf``/``allOf``/``oneOf`` combinators, capped at
    ``_MAX_PARAM_DEPTH``.
    """
    if depth > _MAX_PARAM_DEPTH or not isinstance(schema, dict):
        return

    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            child = f"{path}.{name}" if path else str(name)
            if _DANGEROUS_PARAM_RE.search(str(name)):
                ops_only = isinstance(sub, dict) and _is_ops_only(sub)
                out.append((child, str(name), ops_only))
            if isinstance(sub, dict):
                _walk_schema_props(sub, child, depth + 1, out)

    items = schema.get("items")
    if isinstance(items, dict):
        _walk_schema_props(items, f"{path}[]", depth + 1, out)

    for combinator in ("anyOf", "allOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for i, branch in enumerate(branches):
                _walk_schema_props(branch, f"{path}<{combinator}[{i}]>", depth + 1, out)


def _find_schema_objects(node: Any, depth: int, acc: list[dict[str, Any]]) -> None:
    """Walk arbitrary parsed JSON, collecting tool-schema container objects.

    A container is the dict value of any ``inputSchema`` / ``input_schema`` /
    ``parameters`` key, regardless of nesting depth (covers MCP
    ``tools[].inputSchema``, Anthropic ``input_schema``, and OpenAI
    ``function.parameters`` shapes).
    """
    if depth > _MAX_DOC_DEPTH:
        return
    if isinstance(node, dict):
        for key, val in node.items():
            if key in _SCHEMA_KEYS and isinstance(val, dict):
                acc.append(val)
            _find_schema_objects(val, depth + 1, acc)
    elif isinstance(node, list):
        for item in node:
            _find_schema_objects(item, depth + 1, acc)


def _scan_document(data: Any) -> list[tuple[str, str, bool]]:
    """Return dangerous-param hits for one parsed JSON document.

    Inspects every tool-schema container found anywhere in the document, plus
    the top-level object itself when it is a bare JSON schema (has
    ``properties``), so a standalone input-schema file is also covered.
    """
    schemas: list[dict[str, Any]] = []
    _find_schema_objects(data, 0, schemas)
    # Bare schema file: the document itself is the input schema.
    if isinstance(data, dict) and isinstance(data.get("properties"), dict):
        schemas.append(data)

    hits: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    for schema in schemas:
        local: list[tuple[str, str, bool]] = []
        _walk_schema_props(schema, "", 0, local)
        for param_path, name, ops_only in local:
            # Dedupe identical (path, name) pairs across overlapping containers.
            dedupe_key = f"{param_path}|{ops_only}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            hits.append((param_path, name, ops_only))
    return hits


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan JSON tool/function schemas for LLM-settable sandbox-disable params.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for json_path in project_root.rglob("*.json"):
        try:
            rel_parts = json_path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not json_path.is_file():
            continue

        try:
            if json_path.stat().st_size > 1_000_000:
                continue
            raw_text = json_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if not any(marker in raw_text for marker in _MARKERS):
            continue
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            continue

        rel_path = str(json_path.relative_to(project_root))
        scanned_files.add(rel_path)

        for param_path, name, ops_only in _scan_document(data):
            if ops_only:
                # Allowlisted ops-only flag: documented as not LLM-settable,
                # so the critical finding is suppressed (pass with note).
                continue
            findings.append(make_finding(
                _RULE_ID,
                rel_path,
                (
                    f"tool schema parameter '{param_path}' ({name}) disables or "
                    f"weakens sandboxing and is LLM-settable (present in the "
                    f"model-facing input schema) — CVE-2026-42074 class. "
                    f"If host-only, mark it readOnly/x-aak-sandbox-control: "
                    f"ops-only."
                ),
                find_line_number(raw_text, name),
            ))

    return findings, scanned_files
