"""v0.3.10 product-feature tests — AIVSS scoring, Prisma AIRS coverage,
aak watch dry-run, aak rule lint, coverage page builder."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.cli_modules.rule_lint import run_lint
from agent_audit_kit.scoring.aivss import annotate_sarif, score_finding
from agent_audit_kit.scoring.aivss_schema import AIVSSScore
from agent_audit_kit.translators.prisma_airs import (
    load_catalog,
    map_airs_attack_to_rule,
    summarize as airs_summarize,
)


# -------------------- AIVSS scoring --------------------

def test_aivss_score_returns_v08_record() -> None:
    from agent_audit_kit.rules.builtin import get_rule

    score = score_finding(get_rule("AAK-CREWAI-CVE-2026-2275-001"))
    assert isinstance(score, AIVSSScore)
    assert score.aivss_version == "0.8"
    assert 0.0 <= score.final_score <= 10.0
    assert score.aars.has_tool_use is True


def test_aivss_runtime_ctx_overrides_defaults() -> None:
    from agent_audit_kit.rules.builtin import get_rule

    rule = get_rule("AAK-CREWAI-CVE-2026-2287-001")
    base = score_finding(rule)
    overridden = score_finding(rule, runtime_ctx={"aars": {"human_in_loop": True}})
    assert overridden.final_score < base.final_score


def test_aivss_score_round_trip() -> None:
    from agent_audit_kit.rules.builtin import get_rule

    score = score_finding(get_rule("AAK-LANGCHAIN-PROMPT-LOADER-PATH-001"))
    payload = score.to_dict()
    assert AIVSSScore.from_dict(payload) == score


def test_annotate_sarif_adds_aivss_property() -> None:
    from agent_audit_kit.rules.builtin import get_rule

    sarif = {
        "runs": [
            {
                "results": [
                    {"ruleId": "AAK-CREWAI-CVE-2026-2275-001", "message": {"text": "x"}}
                ]
            }
        ]
    }
    out = annotate_sarif(sarif, get_rule)
    payload = out["runs"][0]["results"][0]["properties"]["aivss_score"]
    assert payload["aivss_version"] == "0.8"


def test_aak_score_cli_round_trip(tmp_path: Path) -> None:
    sarif_in = {
        "runs": [
            {
                "results": [
                    {"ruleId": "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001", "message": {"text": "x"}}
                ]
            }
        ]
    }
    p_in = tmp_path / "in.sarif"
    p_in.write_text(json.dumps(sarif_in), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, ["score", str(p_in), "--aivss"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "aivss_score" in payload["runs"][0]["results"][0]["properties"]


# -------------------- Prisma AIRS coverage --------------------

def test_prisma_airs_catalog_loads() -> None:
    catalog = load_catalog()
    assert catalog
    assert all("airs_attack_id" in a for a in catalog)


def test_prisma_airs_summary_meets_threshold() -> None:
    summary = airs_summarize()
    assert summary["coverage_pct"] >= 60.0
    assert summary["covered"] >= summary["total_static"] * 0.6


def test_prisma_airs_map_returns_rule_ids() -> None:
    rules = map_airs_attack_to_rule({"airs_attack_id": "PA-AIRS-005"})
    assert "AAK-CREWAI-CVE-2026-2275-001" in rules


def test_aak_coverage_prisma_text_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["coverage", "--source", "prisma-airs", "--format", "text"])
    assert result.exit_code == 0, result.output
    assert "Prisma AIRS coverage" in result.output


def test_aak_coverage_prisma_fail_under_strict() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["coverage", "--source", "prisma-airs", "--format", "text", "--fail-under", "200"],
    )
    assert result.exit_code != 0


# -------------------- aak watch (dry-run) --------------------

def test_aak_watch_cve_dry_run_one_iteration_clean() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["watch-cve", "--feeds", "ox", "--dry-run", "--max-iterations", "1", "--interval-seconds", "1"],
    )
    assert result.exit_code == 0


# -------------------- aak rule lint --------------------

def test_rule_lint_clean_today() -> None:
    """v0.3.10 baseline: every existing rule passes the lint."""
    assert run_lint() == []


def test_rule_lint_specific_rule_isolation() -> None:
    out = run_lint(rule_filter="AAK-CREWAI-CVE-2026-2275-001")
    assert out == []


def test_aak_rule_lint_cli_returns_zero_on_clean_registry() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["rule", "lint", "--ci"])
    assert result.exit_code == 0, result.output


# -------------------- coverage page builder --------------------

def test_build_coverage_page_writes_html(tmp_path: Path, monkeypatch) -> None:
    """Build the coverage page into a tmp dir."""
    import scripts.build_coverage_page as bcp

    monkeypatch.setattr(bcp, "OUT_DIR", tmp_path)
    rc = bcp.main()
    assert rc == 0
    assert (tmp_path / "index.html").exists()
    text = (tmp_path / "index.html").read_text()
    assert "AAK coverage" in text
    assert "OX-disclosed CVEs" in text
    assert "Prisma AIRS attack catalog" in text
