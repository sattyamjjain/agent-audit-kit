"""Shared-resource broken-access-control scanner — CVE-2026-44654 class.

Flags tool/function/MCP descriptors that expose a *mutating* operation
(delete / remove / edit / update / overwrite / move) on a file, record, or
resource that is reachable in a **shared or multi-agent** context, when the
tool's input schema carries **no per-actor authorization field** (owner /
actor / authorization / permission / ...). Any agent that can call the tool
could then mutate another principal's resource.

This is the **CVE-2026-44654** class: LibreChat <= 0.8.3 let a shared-agent
editor delete file records via ``DELETE /api/files`` that the owner had reused
across multiple agents (CWE-863 Incorrect Authorization, CVSS 8.1).

Scope: a JSON descriptor scan, not an AST analyzer. It reads tool/function
descriptors (``name`` + optional ``description`` + a parameter schema under
``inputSchema`` / ``input_schema`` / ``parameters``) from JSON files. The
"shared / multi-agent" precondition is inferred from a file-level multi-agent
signal (an ``agents`` collection with more than one member, or a ``shared`` /
``scope: shared|workspace|team|org`` marker) OR from shared-resource language
in the tool's own name/description. A tool annotated
``"x-aak-shared-authz": "global-ok"`` is treated as an intentional global
resource and suppressed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import in_skip_dir, loads_json, make_finding, placed

_RULE_ID = "AAK-AGENT-SHARED-RES-AUTHZ-001"

# Mutating verbs (per the CVE-2026-44654 brief).
_MUTATE_VERBS = frozenset({"delete", "remove", "edit", "update", "overwrite", "move"})
_MUTATE_RE = re.compile(
    r"\b(?:delete|remove|edit|update|overwrite|move)\b", re.IGNORECASE
)
# The same verbs in the third person, the way most tool descriptions are
# written ("Deletes a file shared with the team"), which `_MUTATE_RE` missed.
# Updates, edits and moves are also everyday plural nouns ("progress updates",
# "small focused edits", "the legal moves"; on MCPTox's 353 clean tools the
# nouns outnumber the verbs), so those three count only when an article or a
# quantifier follows, as a verb's object does; deletes, removes and overwrites
# count anywhere.
_MUTATE_THIRD_PERSON_RE = re.compile(
    r"\b(?:deletes|removes|overwrites)\b"
    r"|\b(?:updates|edits|moves)\s+(?:a|an|the|this|that|these|those|its|their|"
    r"your|any|all|each|every|one|existing|specified|selected|given|multiple)\b",
    re.IGNORECASE,
)
# The first word of a tool name. Names are written `<verb>_<object>`, and the
# underscore is a word character, so `_MUTATE_RE` never found `delete` in
# `delete_shared_file`, nor in `deleteSharedFile`; only a hyphenated name gave
# up its verb. Only the leading word is read: a verb further in
# (`get_file_update_time`) names what a read reports.
_NAME_LEAD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
# Resource nouns the mutation acts on — required alongside a verb so a verb in
# unrelated prose (e.g. "update the user on progress") does not match alone.
_RESOURCE_RE = re.compile(
    r"\b(?:file|record|resource|document|doc|entry|item|object|row|entity|"
    r"note|message|artifact|dataset|memory|conversation|thread)s?\b",
    re.IGNORECASE,
)
# Per-actor authorization / ownership fields. Matched against property names.
_AUTHZ_FIELD_RE = re.compile(
    r"owner|actor|principal|author|user[_-]?id|caller|authoriz|permission|"
    r"\bacl\b|tenant|requested[_-]?by|on[_-]?behalf|requester|subject[_-]?id",
    re.IGNORECASE,
)
# Shared / multi-agent language in a tool's own name/description.
_SHARED_TEXT_RE = re.compile(
    r"shared|multi[_-]?agent|cross[_-]?agent|\bteam\b|workspace|collaborat|"
    r"other agents|reused across|org[_-]?wide|tenant",
    re.IGNORECASE,
)

# Explicit opt-out: resource is intentionally global and every agent may mutate.
_GLOBAL_OK = "global-ok"

_SCHEMA_KEYS: tuple[str, ...] = ("inputSchema", "input_schema", "parameters")

_MARKERS: tuple[str, ...] = (
    '"inputSchema"', '"input_schema"', '"parameters"',
    '"tools"', '"agents"', '"name"',
)

_MAX_DOC_DEPTH = 12
_MAX_PARAM_DEPTH = 8


def _collect_property_names(schema: Any, depth: int, acc: set[str]) -> None:
    """Collect every property name in a JSON schema (recursively)."""
    if depth > _MAX_PARAM_DEPTH or not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, sub in props.items():
            acc.add(str(name))
            _collect_property_names(sub, depth + 1, acc)
    items = schema.get("items")
    if isinstance(items, dict):
        _collect_property_names(items, depth + 1, acc)
    for combinator in ("anyOf", "allOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for branch in branches:
                _collect_property_names(branch, depth + 1, acc)


def _has_authz_field(schema: Any) -> bool:
    names: set[str] = set()
    _collect_property_names(schema, 0, names)
    return any(_AUTHZ_FIELD_RE.search(n) for n in names)


def _doc_shared_signal(node: Any, depth: int) -> bool:
    """Return True if the document declares a shared / multi-agent context.

    Signals: an ``agents`` (or ``subagents``) collection with >1 member; a
    truthy ``shared`` flag; or a ``scope`` of shared/workspace/team/org.
    """
    if depth > _MAX_DOC_DEPTH:
        return False
    if isinstance(node, dict):
        for key, val in node.items():
            kl = str(key).lower()
            if kl in ("agents", "subagents"):
                if isinstance(val, list) and len(val) > 1:
                    return True
                if isinstance(val, dict) and len(val) > 1:
                    return True
            if kl == "shared" and val is True:
                return True
            if kl == "scope" and isinstance(val, str) and val.strip().lower() in (
                "shared", "workspace", "team", "org", "organization",
            ):
                return True
            if _doc_shared_signal(val, depth + 1):
                return True
    elif isinstance(node, list):
        for item in node:
            if _doc_shared_signal(item, depth + 1):
                return True
    return False


def _iter_tool_descriptors(
    node: Any,
    depth: int,
    acc: list[tuple[str, str, dict[str, Any]]],
) -> None:
    """Collect (name, description, param_schema) for tool/function descriptors.

    A descriptor is any dict carrying a string ``name`` together with either a
    ``description`` or a parameter-schema container. Handles MCP
    ``tools[].{name,description,inputSchema}``, Anthropic ``input_schema``, and
    OpenAI ``{"type":"function","function":{...}}`` (the inner object is itself
    a descriptor, so the generic walk reaches it).
    """
    if depth > _MAX_DOC_DEPTH:
        return
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str) and name:
            desc = node.get("description")
            desc_str = desc if isinstance(desc, str) else ""
            schema: dict[str, Any] = {}
            for key in _SCHEMA_KEYS:
                val = node.get(key)
                if isinstance(val, dict):
                    schema = val
                    break
            if desc_str or schema or "x-aak-shared-authz" in node:
                # Carry the opt-out marker through on the schema dict so the
                # caller can see it without re-reading the descriptor.
                marker = node.get("x-aak-shared-authz")
                if isinstance(marker, str):
                    schema = {**schema, "__shared_authz_marker__": marker}
                acc.append((name, desc_str, schema))
        for val in node.values():
            _iter_tool_descriptors(val, depth + 1, acc)
    elif isinstance(node, list):
        for item in node:
            _iter_tool_descriptors(item, depth + 1, acc)


def _name_leads_with_verb(name: str) -> bool:
    lead = _NAME_LEAD_RE.match(name.lstrip("_-"))
    return lead is not None and lead.group(0).lower() in _MUTATE_VERBS


def _is_mutating(name: str, description: str) -> bool:
    blob = f"{name} {description}"
    verb = (
        _MUTATE_RE.search(blob)
        or _MUTATE_THIRD_PERSON_RE.search(description)
        or _name_leads_with_verb(name)
    )
    return bool(verb and _RESOURCE_RE.search(blob))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan JSON tool/agent descriptors for shared-resource authz gaps.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for json_path in project_root.rglob("*.json"):
        if in_skip_dir(json_path, project_root):
            continue
        if not json_path.is_file():
            continue

        try:
            if json_path.stat().st_size > 1_000_000:
                continue
            raw_text = json_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if not all(m in raw_text for m in ('"name"',)) or not any(
            m in raw_text for m in _MARKERS
        ):
            continue
        try:
            data = loads_json(raw_text, json_path)
        except json.JSONDecodeError:
            continue

        rel_path = str(json_path.relative_to(project_root))
        scanned_files.add(rel_path)

        doc_shared = _doc_shared_signal(data, 0)

        descriptors: list[tuple[str, str, dict[str, Any]]] = []
        _iter_tool_descriptors(data, 0, descriptors)

        seen: set[str] = set()
        unplaced: list[tuple[Finding, str]] = []
        for name, description, schema in descriptors:
            if not _is_mutating(name, description):
                continue
            shared = doc_shared or bool(_SHARED_TEXT_RE.search(f"{name} {description}"))
            if not shared:
                continue
            if schema.get("__shared_authz_marker__") == _GLOBAL_OK:
                continue  # intentional global resource — suppressed
            if _has_authz_field(schema):
                continue
            if name in seen:
                continue
            seen.add(name)
            unplaced.append((make_finding(
                _RULE_ID,
                rel_path,
                (
                    f"tool '{name}' performs a mutating op on a shared/"
                    f"multi-agent resource but exposes no owner/actor/"
                    f"authorization field — CVE-2026-44654 class. Add and "
                    f"enforce a per-actor authorization parameter, or annotate "
                    f"the tool x-aak-shared-authz: global-ok if intentional."
                ),
            ), name))
        # Every reported tool's line in one pass over the file, not one search of it per tool.
        findings.extend(placed(raw_text, unplaced))

    return findings, scanned_files
