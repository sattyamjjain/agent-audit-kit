"""Tests for AAK-MCP-SANDBOX-SELFDISABLE-001 (CVE-2026-42074 class).

A tool/function JSON schema must not expose a parameter that disables or
weakens sandboxing/isolation in its model-facing ``properties`` — the LLM is
an untrusted principal and can set it in any tool_use response. OpenClaude
< 0.5.1 shipped ``dangerouslyDisableSandbox`` in the BashTool input schema
(CWE-284 / CWE-306, CVSS 9.8).

Fixtures pin the contract: a vulnerable schema fires, a clean schema passes,
and an allowlisted ops-only flag passes (suppressed by annotation).
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.sandbox_self_disable import scan

RULE_ID = "AAK-MCP-SANDBOX-SELFDISABLE-001"


def _write(tmp_path: Path, name: str, obj: object) -> None:
    (tmp_path / name).write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_anchor() -> None:
    assert RULE_ID in RULES, f"{RULE_ID} missing from RULES registry"
    rule = RULES[RULE_ID]
    assert rule.severity.value == "critical"
    assert "CVE-2026-42074" in rule.cve_references
    assert "MCP06:2025" in rule.owasp_mcp_references
    assert "ASI06" in rule.owasp_agentic_references


# ---------------------------------------------------------------------------
# Vulnerable — must fire.
# ---------------------------------------------------------------------------


def test_dangerously_disable_sandbox_is_flagged(tmp_path: Path) -> None:
    """The exact CVE-2026-42074 shape: BashTool input schema exposes
    `dangerouslyDisableSandbox` as a model-fillable property."""
    _write(tmp_path, "tools.json", {
        "name": "bash",
        "description": "Run a shell command.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "the command"},
                "dangerouslyDisableSandbox": {
                    "type": "boolean",
                    "description": "skip the sandbox",
                },
            },
        },
    })
    findings, scanned = scan(tmp_path)
    assert "tools.json" in scanned
    hits = _hits(findings)
    assert hits, f"dangerouslyDisableSandbox should fire {RULE_ID}"
    assert "dangerouslyDisableSandbox" in hits[0].evidence


def test_snake_case_variants_are_flagged(tmp_path: Path) -> None:
    """OpenAI function-calling shape with `parameters`, snake_case names."""
    _write(tmp_path, "fn.json", {
        "type": "function",
        "function": {
            "name": "exec",
            "parameters": {
                "type": "object",
                "properties": {
                    "disable_sandbox": {"type": "boolean"},
                    "no_sandbox": {"type": "boolean"},
                    "allow_unsafe": {"type": "boolean"},
                    "skip_isolation": {"type": "boolean"},
                },
            },
        },
    })
    findings, _ = scan(tmp_path)
    names = {h.evidence for h in _hits(findings)}
    blob = " ".join(names)
    for expected in ("disable_sandbox", "no_sandbox", "allow_unsafe", "skip_isolation"):
        assert expected in blob, f"{expected} not flagged"


def test_nested_object_param_is_flagged(tmp_path: Path) -> None:
    """A dangerous flag nested inside an object parameter is still reached."""
    _write(tmp_path, "nested.json", {
        "name": "run",
        "input_schema": {
            "type": "object",
            "properties": {
                "opts": {
                    "type": "object",
                    "properties": {
                        "dangerously_disable": {"type": "boolean"},
                    },
                },
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert _hits(findings), "nested dangerous param should fire"


def test_bare_schema_file_is_flagged(tmp_path: Path) -> None:
    """A standalone JSON-schema file (no tool wrapper) is also scanned."""
    _write(tmp_path, "schema.json", {
        "type": "object",
        "properties": {"no-sandbox": {"type": "boolean"}},
    })
    findings, _ = scan(tmp_path)
    assert _hits(findings), "bare schema file with no-sandbox should fire"


# ---------------------------------------------------------------------------
# Clean — must pass.
# ---------------------------------------------------------------------------


def test_clean_schema_passes(tmp_path: Path) -> None:
    _write(tmp_path, "clean.json", {
        "name": "bash",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout_ms": {"type": "integer"},
            },
        },
    })
    findings, scanned = scan(tmp_path)
    assert "clean.json" in scanned
    assert not _hits(findings), "clean schema must produce zero findings"


def test_dangerous_name_in_description_only_is_not_flagged(tmp_path: Path) -> None:
    """The match is on the parameter *name*, not free text — a description
    mentioning 'disable sandbox' must not fire (that's tool-poisoning's job)."""
    _write(tmp_path, "desc.json", {
        "name": "bash",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Do not disable sandbox or skip isolation.",
                },
            },
        },
    })
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "description text must not trigger the name rule"


# ---------------------------------------------------------------------------
# Allowlisted ops-only flag — must pass (suppressed by annotation).
# ---------------------------------------------------------------------------


def test_ops_only_annotation_suppresses_finding(tmp_path: Path) -> None:
    """A sandbox-control flag declared not-LLM-settable (operator-only) passes:
    the property is documented as host-set, so it is not in scope for the
    untrusted-principal threat. Three accepted annotations are exercised."""
    _write(tmp_path, "ops.json", {
        "name": "bash",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "disable_sandbox": {
                    "type": "boolean",
                    "x-aak-sandbox-control": "ops-only",
                },
                "no_sandbox": {"type": "boolean", "readOnly": True},
                "allow_unsafe": {"type": "boolean", "x-llm-settable": False},
            },
        },
    })
    findings, scanned = scan(tmp_path)
    assert "ops.json" in scanned
    assert not _hits(findings), (
        "ops-only / readOnly / x-llm-settable:false flags must be suppressed; "
        f"got {[f.evidence for f in _hits(findings)]}"
    )


def test_ops_only_does_not_mask_a_sibling_llm_settable_flag(tmp_path: Path) -> None:
    """An allowlisted flag must not suppress a *different* dangerous flag that
    is still LLM-settable in the same schema."""
    _write(tmp_path, "mixed.json", {
        "name": "bash",
        "inputSchema": {
            "type": "object",
            "properties": {
                "no_sandbox": {"type": "boolean", "readOnly": True},
                "dangerouslyDisableSandbox": {"type": "boolean"},
            },
        },
    })
    findings, _ = scan(tmp_path)
    hits = _hits(findings)
    assert hits, "the LLM-settable flag must still fire"
    assert all("dangerouslyDisableSandbox" in h.evidence for h in hits)
    assert not any("no_sandbox" in h.evidence for h in hits)


# ---------------------------------------------------------------------------
# Non-schema JSON is ignored.
# ---------------------------------------------------------------------------


def test_unrelated_json_is_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", {
        "name": "my-app",
        "scripts": {"no_sandbox": "echo hi"},
    })
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "a non-schema key named no_sandbox must not fire"
