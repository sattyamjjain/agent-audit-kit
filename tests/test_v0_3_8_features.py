"""Smoke tests for the v0.3.8 features (corpus, diff, suggest, preset registry)."""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.remediation.engine import sarif_to_markdown
from agent_audit_kit.sarif.diff import diff_sarif


def _sarif(results: list[dict]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0",
        "version": "2.1.0",
        "runs": [{"results": results}],
    }


def _result(rule: str, file: str, line: int) -> dict:
    return {
        "ruleId": rule,
        "message": {"text": f"finding for {rule}"},
        "level": "warning",
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}
        ],
    }


# -------------------- aak diff --------------------

def test_diff_classifies_three_buckets() -> None:
    base = _sarif([_result("AAK-X", "a.py", 1), _result("AAK-Y", "a.py", 2)])
    cur = _sarif([_result("AAK-X", "a.py", 1), _result("AAK-Z", "a.py", 3)])
    out = diff_sarif(base, cur)
    summary = out["runs"][0]["properties"]["aak_diff_summary"]
    assert summary == {
        "newly_introduced": 1,
        "newly_resolved": 1,
        "still_present": 1,
    }
    states = sorted(r["properties"]["aak_diff_state"] for r in out["runs"][0]["results"])
    assert states == ["newly_introduced", "newly_resolved", "still_present"]


def test_diff_handles_empty_baseline() -> None:
    base = _sarif([])
    cur = _sarif([_result("AAK-X", "a.py", 1)])
    out = diff_sarif(base, cur)
    assert out["runs"][0]["properties"]["aak_diff_summary"]["newly_introduced"] == 1


# -------------------- aak suggest --------------------

def test_suggest_emits_per_rule_section(tmp_path: Path) -> None:
    sarif = _sarif([_result("AAK-PRTITLE-IPI-001", "src/agent.py", 4)])
    md = sarif_to_markdown(json.dumps(sarif), pr_mode=True)
    assert "AAK-PRTITLE-IPI-001" in md
    assert "src/agent.py:4" in md


def test_suggest_no_findings_returns_clean_message() -> None:
    md = sarif_to_markdown(json.dumps(_sarif([])), pr_mode=False)
    assert "no findings" in md.lower()


# -------------------- corpus manifest --------------------

def test_corpus_manifest_in_repo_validates() -> None:
    """The shipped public/corpora/manifest.json must parse + name two corpora."""
    manifest = Path(__file__).resolve().parent.parent / "public" / "corpora" / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    ids = {entry["id"] for entry in data["corpora"]}
    assert "ipi_wild_2026_04" in ids
    assert "fhi_universal_suffixes" in ids


# -------------------- VS Code extension surface --------------------

def test_vscode_sarif_reader_exists() -> None:
    """The new vscode-extension/src/sarifReader.ts ships with the PR."""
    f = Path(__file__).resolve().parent.parent / "vscode-extension" / "src" / "sarifReader.ts"
    assert f.is_file()
    text = f.read_text(encoding="utf-8")
    assert "applySarifToDiagnostics" in text
    assert "registerSarifCommands" in text


# -------------------- comparison doc --------------------

def test_gitlab_comparison_doc_exists() -> None:
    f = Path(__file__).resolve().parent.parent / "docs" / "comparison-gitlab-agentic-sast.md"
    assert f.is_file()
    text = f.read_text(encoding="utf-8")
    assert "AgentAuditKit" in text
    assert "GitLab" in text


# -------------------- backfill audit --------------------

def test_backfill_cve_property_check_passes() -> None:
    import importlib.util
    import sys

    repo_root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "backfill_cve_property", repo_root / "scripts" / "backfill_cve_property.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["backfill_cve_property"] = module
    spec.loader.exec_module(module)
    rc = module.main(["--check"])
    assert rc == 0, "CVE property drift — see stderr"
