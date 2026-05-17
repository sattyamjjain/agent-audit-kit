"""v0.3.19 — Suggestion 1 + Suggestion 3 of 2026-05-17 daily prompt.

Suggestion 1: AAK-MCP-TOOL-UNSAFE-EVAL-001 — AST detector for
`eval()`/`exec()`/`compile()` calls inside `@mcp.tool` handlers
(generalization of v0.3.18's CVE-2026-44717 pin row).

Suggestion 3: AAK-MCP-OPENAPI-{LAZY,BLOATED,TANGLED}-* — Hermes-paper
smell category (arXiv:2605.14312, EASE 2026).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.mcp_tool_unsafe_eval import scan as eval_scan
from agent_audit_kit.scanners.openapi_smells import scan as oas_scan

FIXTURES = Path(__file__).parent / "fixtures"
EVAL_FIXTURES = FIXTURES / "mcp_tool_unsafe_eval"
OAS_FIXTURES = FIXTURES / "openapi_smells"

EVAL_RULE = "AAK-MCP-TOOL-UNSAFE-EVAL-001"
LAZY = "AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001"
BLOATED = "AAK-MCP-OPENAPI-BLOATED-PARAMS-001"
TANGLED = "AAK-MCP-OPENAPI-TANGLED-METHODS-001"


# -------------------- Suggestion 1: unsafe eval inside @mcp.tool --------------------


def test_unsafe_eval_inside_mcp_tool_fires(tmp_path: Path) -> None:
    """@mcp.tool function with `eval(expression)` must fire CRITICAL."""
    shutil.copy(EVAL_FIXTURES / "eval_unsafe.py", tmp_path / "eval_unsafe.py")
    findings, _ = eval_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == EVAL_RULE]
    # Two unsafe calls: eval(expression) + exec(code) — expect both to fire.
    assert len(fires) == 2
    for f in fires:
        assert f.severity.name == "CRITICAL"
        assert "expression" in f.evidence or "code" in f.evidence


def test_safe_eval_via_ast_literal_eval_passes(tmp_path: Path) -> None:
    """@mcp.tool function using `ast.literal_eval` must not fire."""
    shutil.copy(EVAL_FIXTURES / "eval_safe.py", tmp_path / "eval_safe.py")
    findings, _ = eval_scan(tmp_path)
    assert not any(f.rule_id == EVAL_RULE for f in findings)


def test_eval_outside_mcp_tool_decorator_passes(tmp_path: Path) -> None:
    """`eval()` in a function NOT decorated as @mcp.tool must not fire."""
    shutil.copy(EVAL_FIXTURES / "no_tool_decorator.py", tmp_path / "internal.py")
    findings, _ = eval_scan(tmp_path)
    assert not any(f.rule_id == EVAL_RULE for f in findings)


# -------------------- Suggestion 3: OpenAPI smells (Hermes paper) -----------------


def test_openapi_smells_fire_on_smelly_spec(tmp_path: Path) -> None:
    """Hermes-style smelly OpenAPI spec must fire all 3 smell rules."""
    shutil.copy(OAS_FIXTURES / "smelly.openapi.yaml", tmp_path / "openapi.yaml")
    findings, scanned = oas_scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert LAZY in rule_ids
    assert BLOATED in rule_ids
    assert TANGLED in rule_ids
    assert "openapi.yaml" in scanned


def test_clean_openapi_passes(tmp_path: Path) -> None:
    """Well-authored OpenAPI must not fire any smell."""
    shutil.copy(OAS_FIXTURES / "clean.openapi.yaml", tmp_path / "openapi.yaml")
    findings, _ = oas_scan(tmp_path)
    smell_ids = {LAZY, BLOATED, TANGLED}
    assert not any(f.rule_id in smell_ids for f in findings)


def test_openapi_smell_no_spec_no_fire(tmp_path: Path) -> None:
    """No OpenAPI file in project → no fires."""
    (tmp_path / "README.md").write_text("# nothing here\n")
    findings, _ = oas_scan(tmp_path)
    smell_ids = {LAZY, BLOATED, TANGLED}
    assert not any(f.rule_id in smell_ids for f in findings)


def test_openapi_tangled_post_on_get_path_fires(tmp_path: Path) -> None:
    """Verify the verb-method conflict arm specifically fires."""
    (tmp_path / "openapi.yaml").write_text(
        "openapi: 3.1.0\n"
        "info: { title: T, version: '0.1' }\n"
        "paths:\n"
        "  /get/items:\n"
        "    post:\n"
        "      description: A long enough description so LAZY does not also fire here for sure.\n"
        "      responses: { '200': { description: OK } }\n",
        encoding="utf-8",
    )
    findings, _ = oas_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == TANGLED]
    assert len(fires) == 1
    assert "/get/items" in fires[0].evidence
