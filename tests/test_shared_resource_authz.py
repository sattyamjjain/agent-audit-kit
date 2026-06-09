"""Tests for AAK-AGENT-SHARED-RES-AUTHZ-001 (CVE-2026-44654 class).

A tool exposing a mutating op (delete/remove/edit/update/overwrite/move) on a
file/record/resource reachable in a shared or multi-agent context, with no
per-actor authorization field, is a broken-access-control gap: any agent can
mutate another principal's resource. LibreChat <= 0.8.3 let a shared-agent
editor delete file records the owner reused across agents (CWE-863, CVSS 8.1).

Fixtures pin the contract: a shared `delete_file(record_id)` with no actor
field fires; the same with an explicit owner/authorization param passes; and a
read-only op passes.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.shared_resource_authz import scan

RULE_ID = "AAK-AGENT-SHARED-RES-AUTHZ-001"


def _write(tmp_path: Path, name: str, obj: object) -> None:
    (tmp_path / name).write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


def _multi_agent_cfg(tool: dict) -> dict:
    """A config with >1 agent sharing one MCP server/tool (the CVE shape)."""
    return {
        "agents": [
            {"name": "editor-a", "mcp": "files"},
            {"name": "editor-b", "mcp": "files"},
        ],
        "mcpServers": {
            "files": {"command": "node", "args": ["files.js"], "tools": [tool]},
        },
    }


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_anchor() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-44654" in rule.cve_references
    assert "ASI04" in rule.owasp_agentic_references


# ---------------------------------------------------------------------------
# Vulnerable — must fire.
# ---------------------------------------------------------------------------


def test_shared_delete_file_without_actor_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-44654 shape: a shared multi-agent config exposes
    delete_file(record_id) with no owner/actor field."""
    _write(tmp_path, "agents.json", _multi_agent_cfg({
        "name": "delete_file",
        "description": "Delete a file record by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"record_id": {"type": "string"}},
        },
    }))
    findings, scanned = scan(tmp_path)
    assert "agents.json" in scanned
    hits = _hits(findings)
    assert hits, f"shared delete_file without actor should fire {RULE_ID}"
    assert "delete_file" in hits[0].evidence


def test_shared_language_in_description_is_flagged(tmp_path: Path) -> None:
    """Shared context inferred from the tool's own description (single-agent
    file, but the resource is explicitly shared across agents)."""
    _write(tmp_path, "tool.json", {
        "name": "overwrite_document",
        "description": "Overwrite a document in the shared team workspace.",
        "parameters": {
            "type": "object",
            "properties": {"doc_id": {"type": "string"}, "body": {"type": "string"}},
        },
    })
    findings, _ = scan(tmp_path)
    assert _hits(findings), "shared-language description should fire"


def test_various_mutating_verbs_fire(tmp_path: Path) -> None:
    for verb, tool in (
        ("remove", "remove_record"),
        ("update", "update_entry"),
        ("move", "move_object"),
        ("edit", "edit_note"),
    ):
        sub = tmp_path / verb
        sub.mkdir()
        _write(sub, "a.json", _multi_agent_cfg({
            "name": tool,
            "description": f"{verb} a {tool.split('_')[1]}.",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
        }))
        findings, _ = scan(sub)
        assert _hits(findings), f"{verb} should fire ({tool})"


# ---------------------------------------------------------------------------
# Safe — must pass.
# ---------------------------------------------------------------------------


def test_explicit_owner_param_passes(tmp_path: Path) -> None:
    """Same shared delete_file, but with an explicit owner_id authz param."""
    _write(tmp_path, "agents.json", _multi_agent_cfg({
        "name": "delete_file",
        "description": "Delete a file record by id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string"},
                "owner_id": {"type": "string"},
            },
        },
    }))
    findings, scanned = scan(tmp_path)
    assert "agents.json" in scanned
    assert not _hits(findings), "an owner_id authz param must clear the finding"


def test_authorization_param_passes(tmp_path: Path) -> None:
    _write(tmp_path, "agents.json", _multi_agent_cfg({
        "name": "edit_record",
        "description": "Edit a shared record.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string"},
                "on_behalf_of": {"type": "string"},
            },
        },
    }))
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "on_behalf_of must clear the finding"


def test_read_only_op_passes(tmp_path: Path) -> None:
    """A read-only op (get/read) in the same shared config must not fire."""
    _write(tmp_path, "agents.json", _multi_agent_cfg({
        "name": "get_file",
        "description": "Read a file record by id.",
        "inputSchema": {"type": "object", "properties": {"record_id": {"type": "string"}}},
    }))
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "read-only op must not fire"


def test_mutating_but_not_shared_passes(tmp_path: Path) -> None:
    """Single-agent (no multi-agent signal, no shared language) must not fire —
    the threat is specifically *shared* resource access."""
    _write(tmp_path, "solo.json", {
        "mcpServers": {
            "files": {
                "command": "node",
                "tools": [{
                    "name": "delete_file",
                    "description": "Delete a file record by id.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"record_id": {"type": "string"}},
                    },
                }],
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "non-shared context must not fire"


def test_global_ok_annotation_suppresses(tmp_path: Path) -> None:
    """A resource intentionally global to all agents is opt-out suppressed."""
    _write(tmp_path, "agents.json", _multi_agent_cfg({
        "name": "delete_file",
        "description": "Delete a shared file record.",
        "x-aak-shared-authz": "global-ok",
        "inputSchema": {"type": "object", "properties": {"record_id": {"type": "string"}}},
    }))
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "global-ok annotation must suppress the finding"


def test_verb_without_resource_noun_passes(tmp_path: Path) -> None:
    """A mutate verb with no resource noun (e.g. 'update the user on status')
    must not fire — both a verb and a resource are required."""
    _write(tmp_path, "agents.json", _multi_agent_cfg({
        "name": "notify_progress",
        "description": "Update the user on task progress via a status ping.",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}},
    }))
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "verb without a resource noun must not fire"
