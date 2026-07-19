"""Guards for the State of MCP 2026 research report.

Ties REPORT.md to results.json so the published numbers cannot drift from the
committed aggregate, and checks the corpus meets issue #23's 1,000-server target.
Fast: reads committed artifacts + a 2-config smoke of the harness (no full scan).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RESEARCH = REPO / "research" / "state-of-mcp-2026"
RESULTS = RESEARCH / "results.json"
REPORT = RESEARCH / "REPORT.md"
MANIFEST = RESEARCH / "corpus" / "registry-manifest.json"


def _results() -> dict:
    return json.loads(RESULTS.read_text(encoding="utf-8"))


def test_corpus_meets_1000_target() -> None:
    d = _results()
    assert d["distinct_configs_scanned"] >= 1000, d["distinct_configs_scanned"]


def test_report_headline_numbers_match_results() -> None:
    d = _results()
    report = REPORT.read_text(encoding="utf-8")
    n = d["distinct_configs_scanned"]
    # The report must cite the exact corpus size and the key metric numerators.
    assert f"{n:,}" in report, f"REPORT.md must cite corpus size {n:,}"
    ap = d["auth_profile_2026_07_28"]
    no_auth = ap["no_authentication"]
    assert f"{no_auth['n']} of {n:,}" in report or f"{no_auth['n']} of {n}" in report
    static = ap["remote_auth_static_credential"]
    assert f"{static['n']} of {static['denominator']}" in report
    prm = ap["rfc9728_prm_discovery"]
    assert f"{prm['n']} of {n:,}" in report  # 0 of 1,374


def test_auth_profile_metrics_carry_n_and_denominator() -> None:
    ap = _results()["auth_profile_2026_07_28"]
    for name, m in ap.items():
        assert set(m) >= {"n", "denominator", "pct"}, f"{name} missing n/denominator/pct"
        assert m["denominator"] >= m["n"], name


def test_registry_manifest_records_provenance() -> None:
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert m["servers"], "manifest has no servers"
    required = {"name", "transport", "auth_mode", "source_url", "fetched_at"}
    for s in m["servers"][:50]:
        assert required <= set(s), f"provenance fields missing on {s.get('name')}"


def _load_run_report():
    spec = importlib.util.spec_from_file_location("somcp_run_report", RESEARCH / "run_report.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_harness_aggregate_smoke(tmp_path: Path) -> None:
    """The harness runs, dedups, and emits the metric shape on a tiny corpus."""
    mod = _load_run_report()
    corpus = tmp_path / "data"
    corpus.mkdir()
    (corpus / "noauth.json").write_text(
        json.dumps({"mcpServers": {"r": {"type": "http", "url": "https://x/mcp"}}}),
        encoding="utf-8",
    )
    (corpus / "stdio.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "python", "args": ["a.py"]}}}),
        encoding="utf-8",
    )
    data = mod.aggregate(corpus, None)
    assert data["distinct_configs_scanned"] == 2
    assert "no_authentication" in data["auth_profile_2026_07_28"]
    # The remote no-auth config must register as no-auth.
    assert data["auth_profile_2026_07_28"]["no_authentication"]["n"] == 1


def test_harness_is_deterministic(tmp_path: Path) -> None:
    """Two aggregations of the same corpus are byte-identical (the report's core claim)."""
    mod = _load_run_report()
    corpus = tmp_path / "data"
    corpus.mkdir()
    for i in range(3):
        (corpus / f"c{i}.json").write_text(
            json.dumps({"mcpServers": {f"s{i}": {"type": "http", "url": f"https://x{i}/mcp",
                                                 "headers": {"Authorization": "Bearer t"}}}}),
            encoding="utf-8",
        )
    a = json.dumps(mod.aggregate(corpus, None), sort_keys=False)
    b = json.dumps(mod.aggregate(corpus, None), sort_keys=False)
    assert a == b
