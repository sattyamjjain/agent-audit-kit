"""OpenVEX emitter — determinism, purl join, status honesty.

The guard that matters most here is `test_not_affected_never_appears`: it
sweeps every fixture in the tree, not a curated list, so a future change that
starts asserting `not_affected` fails loudly instead of quietly shipping a
claim the scanner cannot support.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.sbom import emit_cyclonedx
from agent_audit_kit.output.vex import CONTEXT, emit_openvex

FIXTURES = Path(__file__).parent / "fixtures"

# Existing fixtures, one per status arm. `vulnerable` pins mcp-grafana at
# 1.0.0 (below the 1.1.0 fix floor); `patched` pins it at 1.1.0; kong_konnect
# pins a package the range table does not cover.
AFFECTED_FIXTURE = FIXTURES / "cves" / "cve-2026-19516-mcp-grafana" / "vulnerable"
FIXED_FIXTURE = FIXTURES / "cves" / "cve-2026-19516-mcp-grafana" / "patched"
UNDER_INVESTIGATION_FIXTURE = FIXTURES / "kong_konnect"

PINNED_TS = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)


def _emit(project: Path, timestamp: datetime | None = PINNED_TS) -> dict:
    return json.loads(emit_openvex(project, run_scan(project), timestamp=timestamp))


def _statuses(doc: dict) -> dict[str, str]:
    return {s["vulnerability"]["name"]: s["status"] for s in doc["statements"]}


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_emit_is_byte_identical_across_runs() -> None:
    first = emit_openvex(AFFECTED_FIXTURE, run_scan(AFFECTED_FIXTURE), timestamp=PINNED_TS)
    second = emit_openvex(AFFECTED_FIXTURE, run_scan(AFFECTED_FIXTURE), timestamp=PINNED_TS)
    assert first == second


def test_document_id_is_stable_and_content_addressed() -> None:
    doc = _emit(AFFECTED_FIXTURE)
    other = _emit(AFFECTED_FIXTURE, timestamp=datetime(2030, 1, 1, tzinfo=timezone.utc))
    # The id hashes the statements, not the clock, so a re-emit at a different
    # time keeps the same id while the timestamp moves.
    assert doc["@id"] == other["@id"]
    assert doc["timestamp"] != other["timestamp"]


def test_different_statements_produce_different_ids() -> None:
    assert _emit(AFFECTED_FIXTURE)["@id"] != _emit(FIXED_FIXTURE)["@id"]


def test_timestamp_defaults_to_now_when_not_injected() -> None:
    doc = json.loads(emit_openvex(AFFECTED_FIXTURE, run_scan(AFFECTED_FIXTURE)))
    parsed = datetime.fromisoformat(doc["timestamp"])
    assert parsed.tzinfo is not None
    assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 120


# --------------------------------------------------------------------------
# Purl join with the CycloneDX SBOM
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture", [AFFECTED_FIXTURE, FIXED_FIXTURE, UNDER_INVESTIGATION_FIXTURE]
)
def test_every_vex_product_is_an_sbom_component(fixture: Path) -> None:
    doc = _emit(fixture)
    sbom = json.loads(emit_cyclonedx(fixture))
    component_purls = {c["purl"] for c in sbom["components"] if "purl" in c}
    assert doc["statements"], f"{fixture} produced no statements to join"
    for statement in doc["statements"]:
        for product in statement["products"]:
            assert product["@id"] in component_purls


def test_join_needs_no_mapping_table() -> None:
    """The two documents are joinable by string equality on purl alone."""
    doc = _emit(AFFECTED_FIXTURE)
    sbom = json.loads(emit_cyclonedx(AFFECTED_FIXTURE))
    joined = [
        (s["vulnerability"]["name"], c["name"])
        for s in doc["statements"]
        for c in sbom["components"]
        if c.get("purl") == s["products"][0]["@id"]
    ]
    assert joined
    assert all(name == "mcp-grafana" for _, name in joined)


def test_source_key_does_not_change_sbom_output() -> None:
    """`_discover_mcp_packages` grew a `source` key; no emitter may leak it."""
    for fixture in (AFFECTED_FIXTURE, FIXED_FIXTURE, UNDER_INVESTIGATION_FIXTURE):
        assert "source" not in emit_cyclonedx(fixture)
        from agent_audit_kit.output.sbom import emit_spdx

        assert "source" not in emit_spdx(fixture)


# --------------------------------------------------------------------------
# Status honesty
# --------------------------------------------------------------------------


def test_vulnerable_pin_is_affected_with_action_statement() -> None:
    doc = _emit(AFFECTED_FIXTURE)
    assert _statuses(doc)["CVE-2026-19516"] == "affected"
    for statement in doc["statements"]:
        if statement["status"] == "affected":
            assert statement["action_statement"].strip()


def test_pin_at_or_above_fix_floor_is_fixed() -> None:
    doc = _emit(FIXED_FIXTURE)
    assert _statuses(doc)["CVE-2026-19516"] == "fixed"
    assert all(s["status"] == "fixed" for s in doc["statements"])


def test_fixed_is_reachable_without_any_finding() -> None:
    """A package at the fix floor produces no finding at all.

    This is why the CVE universe is not drawn from findings alone: a
    findings-only universe makes `fixed` unreachable by construction.
    """
    result = run_scan(FIXED_FIXTURE)
    assert not [c for f in result.findings for c in f.cve_references]
    assert _emit(FIXED_FIXTURE)["statements"]


def test_unresolvable_range_is_under_investigation() -> None:
    doc = _emit(UNDER_INVESTIGATION_FIXTURE)
    assert _statuses(doc)["CVE-2026-13341"] == "under_investigation"


def test_under_investigation_carries_no_action_statement() -> None:
    for statement in _emit(UNDER_INVESTIGATION_FIXTURE)["statements"]:
        if statement["status"] == "under_investigation":
            assert "action_statement" not in statement


def test_only_the_three_permitted_statuses_are_emitted() -> None:
    seen = set()
    for fixture in (AFFECTED_FIXTURE, FIXED_FIXTURE, UNDER_INVESTIGATION_FIXTURE):
        seen |= {s["status"] for s in _emit(fixture)["statements"]}
    assert seen <= {"affected", "fixed", "under_investigation"}


def test_unrelated_cves_do_not_cross_multiply_into_products() -> None:
    """A CVE the range table does not tie to this package produces no statement.

    Saying anything there would mean asserting `not_affected`.
    """
    doc = _emit(AFFECTED_FIXTURE)
    named = {s["vulnerability"]["name"] for s in doc["statements"]}
    assert named == {"CVE-2026-19516", "CVE-2026-15583"}


# --------------------------------------------------------------------------
# The honesty guard
# --------------------------------------------------------------------------


def _fixture_dirs() -> list[Path]:
    dirs = [d for d in FIXTURES.rglob("*") if d.is_dir()]
    return [FIXTURES, *dirs]


def test_not_affected_never_appears_in_any_emitted_document() -> None:
    """Sweep every fixture directory in the tree, not a curated list."""
    checked = 0
    statements = 0
    for project in _fixture_dirs():
        try:
            payload = emit_openvex(project, run_scan(project), timestamp=PINNED_TS)
        except Exception:  # noqa: BLE001 - a fixture that cannot scan is not this test's subject
            continue
        checked += 1
        statements += len(json.loads(payload)["statements"])
        assert "not_affected" not in payload, f"not_affected emitted for {project}"
    assert checked > 50, f"guard only swept {checked} fixtures; it is not doing its job"
    # Without this the guard passes vacuously: an emitter that returned an
    # empty document for every project would satisfy the assertion above while
    # saying nothing at all.
    assert statements >= 5, f"sweep produced only {statements} statements; emitter may be inert"


def test_emitter_module_documents_the_refusal() -> None:
    from agent_audit_kit.output import vex

    assert vex.__doc__ is not None
    assert "not_affected" in vex.__doc__
    assert "justification" in vex.__doc__


# --------------------------------------------------------------------------
# Schema shape
# --------------------------------------------------------------------------


def test_document_carries_every_required_openvex_field() -> None:
    doc = _emit(AFFECTED_FIXTURE)
    for field in ("@context", "@id", "author", "timestamp", "version", "statements"):
        assert field in doc, field
    assert doc["@context"] == CONTEXT
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["author"]
    assert isinstance(doc["version"], int)


def test_every_statement_carries_vulnerability_and_a_product() -> None:
    for fixture in (AFFECTED_FIXTURE, FIXED_FIXTURE, UNDER_INVESTIGATION_FIXTURE):
        for statement in _emit(fixture)["statements"]:
            assert statement["vulnerability"]["name"].startswith("CVE-")
            assert statement["products"]
            assert all(p["@id"] for p in statement["products"])
            assert statement["status"]


def test_author_is_injectable() -> None:
    payload = emit_openvex(
        AFFECTED_FIXTURE, run_scan(AFFECTED_FIXTURE), author="acme-security", timestamp=PINNED_TS
    )
    assert json.loads(payload)["author"] == "acme-security"


def test_document_id_is_under_a_namespace_the_project_controls() -> None:
    # Same reasoning as `documentNamespace` in emit_spdx: an id minted under
    # openvex.dev would claim a namespace this project does not own.
    assert _emit(AFFECTED_FIXTURE)["@id"].startswith(
        "https://sattyamjjain.github.io/agent-audit-kit/vex/"
    )


def test_empty_project_still_emits_a_valid_document(tmp_path: Path) -> None:
    doc = json.loads(emit_openvex(tmp_path, run_scan(tmp_path), timestamp=PINNED_TS))
    assert doc["@context"] == CONTEXT
    assert doc["statements"] == []


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_vex_command_writes_a_document(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    out = tmp_path / "vex.json"
    res = CliRunner().invoke(cli, ["vex", str(AFFECTED_FIXTURE), "-o", str(out)])
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["@context"] == CONTEXT
    assert doc["statements"]


def test_vex_command_exits_zero_despite_findings() -> None:
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    assert run_scan(AFFECTED_FIXTURE).findings
    res = CliRunner().invoke(cli, ["vex", str(AFFECTED_FIXTURE)])
    assert res.exit_code == 0
    assert json.loads(res.output)["statements"]


def test_vex_command_rejects_an_unknown_format() -> None:
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    res = CliRunner().invoke(cli, ["vex", str(AFFECTED_FIXTURE), "--format", "csaf"])
    assert res.exit_code != 0
