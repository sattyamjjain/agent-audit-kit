"""Guards for the State of MCP 2026 research report.

Ties REPORT.md to results.json so the published numbers cannot drift from the
committed aggregate, and checks the corpus meets issue #23's 1,000-server target.
Fast: reads committed artifacts + a 2-config smoke of the harness (no full scan).
"""

from __future__ import annotations

import importlib.util
import json
import re
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
    # The figures are `report:` markers since v1.1; read what a reader sees.
    report = re.sub(
        r"<!--\s*report:[a-z0-9-]+\s*-->(.*?)<!--\s*/report\s*-->",
        lambda m: m.group(1), REPORT.read_text(encoding="utf-8"), flags=re.DOTALL,
    )
    n = d["distinct_configs_scanned"]
    # The report must cite the exact corpus size and the key metric numerators.
    assert f"{n:,}" in report, f"REPORT.md must cite corpus size {n:,}"
    ap = d["auth_profile_2026_07_28"]
    no_auth = ap["no_authentication"]
    assert f"{no_auth['n']:,} of {n:,}" in report
    static = ap["remote_auth_static_credential"]
    assert f"{static['n']:,} of {static['denominator']:,}" in report
    prm = ap["rfc9728_prm_discovery"]
    assert f"{prm['n']:,} of {n:,}" in report  # 0 of 1,374


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


def test_harness_scans_each_config_as_dot_mcp_json(tmp_path: Path, monkeypatch) -> None:
    """Every config is scanned as `.mcp.json`, the name every scanner reads.

    Up to report v1.0 the harness wrote `config.mcp.json`. The supply-chain
    scanner and the CVE pin table open configs by name and never read that one,
    so AAK-SUPPLY-001 and every pin rule went unmeasured on the corpus.
    """
    mod = _load_run_report()
    seen: list[list[str]] = []
    real_run_scan = mod.run_scan

    def spy(root: Path, *args, **kwargs):
        seen.append(sorted(p.name for p in Path(root).iterdir()))
        return real_run_scan(root, *args, **kwargs)

    monkeypatch.setattr(mod, "run_scan", spy)
    corpus = tmp_path / "data"
    corpus.mkdir()
    (corpus / "npx.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "npx", "args": ["-y", "some-mcp-server"]}}}),
        encoding="utf-8",
    )
    data = mod.aggregate(corpus, None)
    assert seen == [[".mcp.json"]]
    # The unpinned launch is reported only when supply_chain reads the file.
    assert "AAK-SUPPLY" in data["rule_family_distribution"]


def test_harness_counts_an_env_secret_once(tmp_path: Path) -> None:
    """AAK-SECRET-007 stands down on `.mcp.json`, where AAK-MCP-003 reports it.

    Under `config.mcp.json` both rules fired on the same env literal, so the
    v1.0 top-ten table listed one finding twice (rows 5 and 6, 70 configs each).
    """
    mod = _load_run_report()
    corpus = tmp_path / "data"
    corpus.mkdir()
    (corpus / "env.json").write_text(
        json.dumps({"mcpServers": {"s": {
            "command": "node", "args": ["server.js"],
            "env": {"SERVICE_API_KEY": "Zq8RkT3vLmN5pW7xY2bC4dF6gH9jK1sQ0aE3uI5o"},
        }}}),
        encoding="utf-8",
    )
    rules = {row["rule_id"] for row in mod.aggregate(corpus, None)["top_misconfigurations"]}
    assert "AAK-MCP-003" in rules
    assert "AAK-SECRET-007" not in rules


def test_owasp_tally_leaves_out_the_advisory_rules(tmp_path: Path) -> None:
    """The OWASP MCP hit rate counts what the top-ten table counts.

    AAK-MCP-ATTEST-001 fires on nearly every config. Counted, it put its own
    OWASP id at 99.9% of the corpus, a figure about the attestation rule rather
    than the servers. Re-derived here from the findings, minus the advisory set.
    """
    from agent_audit_kit.rules.builtin import RULES

    mod = _load_run_report()
    text = json.dumps({"mcpServers": {"r": {"type": "http", "url": "https://x.example/mcp"}}})
    corpus = tmp_path / "data"
    corpus.mkdir()
    (corpus / "remote.json").write_text(text, encoding="utf-8")

    fired = {f.rule_id for f in mod._scan_text(text).findings}
    counted = fired - mod._ADVISORY_RULES
    expected = {ref for rid in counted for ref in RULES[rid].owasp_mcp_references}
    advisory_only = {
        ref for rid in fired & mod._ADVISORY_RULES for ref in RULES[rid].owasp_mcp_references
    } - expected
    assert advisory_only, "the config must trip an OWASP id only an advisory rule carries"
    assert set(mod.aggregate(corpus, None)["owasp_mcp_hit_rate"]) == expected


def test_rule_hit_rate_counts_every_rule_by_config(tmp_path: Path) -> None:
    """Each rule that fired, with the configs it fired on, advisory rules too.

    The top-ten table cannot source a rule that left it, so this map is what a
    per-rule figure outside the top ten is rendered and checked from. Re-derived
    here from each config's findings.
    """
    mod = _load_run_report()
    corpus = tmp_path / "data"
    corpus.mkdir()
    texts = [
        json.dumps({"mcpServers": {"r": {"type": "http", "url": "https://x.example/mcp"}}}),
        json.dumps({"mcpServers": {"r": {"type": "http", "url": "https://y.example/mcp"},
                                   "s": {"command": "npx", "args": ["-y", "pkg"]}}}),
    ]
    for i, text in enumerate(texts):
        (corpus / f"c{i}.json").write_text(text, encoding="utf-8")
    expected: dict[str, int] = {}
    for text in texts:
        for rid in {f.rule_id for f in mod._scan_text(text).findings}:
            expected[rid] = expected.get(rid, 0) + 1
    rates = mod.aggregate(corpus, None)["rule_hit_rate"]
    assert {rid: row["configs"] for rid, row in rates.items()} == expected
    assert set(mod._ADVISORY_RULES) & set(rates), "advisory rules are kept in this map"
    assert rates["AAK-MCP-001"] == {"configs": 2, "pct": 100.0}
    counts = [row["configs"] for row in rates.values()]
    assert counts == sorted(counts, reverse=True)


def test_fp_benchmark_scans_under_the_report_harness_name() -> None:
    """The benign-slice benchmark measures what the report measures."""
    import sys

    fp_dir = REPO / "benchmarks" / "false_positive"
    if str(fp_dir) not in sys.path:
        sys.path.insert(0, str(fp_dir))
    spec = importlib.util.spec_from_file_location("fp_run_name_check", fp_dir / "run.py")
    assert spec and spec.loader
    fp_run = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fp_run)
    assert fp_run.SCAN_FILENAME == _load_run_report().SCAN_FILENAME == ".mcp.json"


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


# ---------------------------------------------------------------------------
# Publication-surface drift guard: the one-canonical-N fence.
#
# test_report_headline_numbers_match_results (above) guards exactly ONE file —
# REPORT.md — which is why the *other* four published surfaces were free to drift,
# and did: the corpus grew (664 -> 2,303) but PREVALENCE / the distribution
# checklist / the docs summary / the README kept quoting 664 / 748 / 1,374. This
# fence extends the same discipline to every surface that quotes the corpus, so the
# next corpus refresh fails the build until the prose follows the aggregate.
#
# Mirrors tests/test_rule_count_sync.py::test_no_stale_hardcoded_counts_in_prose:
# a fixed surface list, a hard denylist of superseded literals, and a narrow,
# commented allowlist for the few lines where a superseded number is a legitimate
# dated / provenance fact rather than a stale headline.
# ---------------------------------------------------------------------------

# Surfaces that quote the corpus. REPORT.md is intentionally NOT here — it is the
# reference test_report_headline_numbers_match_results pins everything else to.
_PUBLICATION_SURFACES = (
    "research/state-of-mcp-2026/PREVALENCE.md",
    "docs/DISTRIBUTION-CHECKLIST.md",
    "docs/STATE-OF-MCP-SECURITY-2026.md",
    "README.md",
)

# Deliberately EXCLUDED from the sweep — frozen or explicitly-dated artifacts whose
# older corpus numbers are historical facts, not current-state claims:
#   - docs/research/mcp-security-baseline-v1.0.md  frozen pre-2026-07-28 baseline (N=1,374)
#   - research/state-of-mcp-2026/baseline/**        committed frozen baseline JSON + .sha256
#   - docs/reports/mcp-2026-07-28-readiness.md      dated 2026-07-18 748-config readiness scan
#   - CHANGELOG.md / CHANGELOG.cves.md              dated release / CVE history
# None are in _PUBLICATION_SURFACES; listed so the omission reads as intentional.
_SWEEP_EXCLUDED = (
    "docs/research/mcp-security-baseline-v1.0.md",
    "research/state-of-mcp-2026/baseline/",
    "docs/reports/mcp-2026-07-28-readiness.md",
    "CHANGELOG.md",
    "CHANGELOG.cves.md",
)

# Superseded corpus-size literals (pre-2,303 headline Ns) and superseded metrics
# (the 664-corpus / 1,374-corpus percentages). A hit in a swept surface, outside
# the allowlist, means the prose is chasing a stale aggregate.
_SUPERSEDED_LITERALS = (
    r"\b664\b", r"\b748\b", r"\b1,?374\b",        # corpus sizes
    r"\b26\.1\b", r"\b35\.1\b", r"\b43\.7\b",     # critical-rate / npx-uvx-rate (664 / 1,374 corpus)
    r"\b43\.4\b", r"\b24\.2\b", r"\b99\.4\b",     # r/netsec npx duplicate / no-auth / MCP07 (664 corpus)
    # report v1.0's no-auth, critical and MCP07 figures (2,303 corpus, superseded by v1.1)
    r"\b52\.1\b", r"\b1,201\b", r"\b52\.7\b", r"\b1,213\b", r"\b99\.8\b",
)

# Lines where a superseded literal is legitimate: (surface, substring on the line).
# Keep this TIGHT — each entry is one place a stale number is allowed to live.
#   - PREVALENCE corpus-provenance line: 664 is the crawl-source subtotal that
#     *composes* the 2,303 corpus (664 crawled + 1,639 registry), not a headline N.
#   - README readiness link: the dated 2026-07-18 748-config point-in-time scan.
_SUPERSEDED_ALLOWLIST = (
    ("research/state-of-mcp-2026/PREVALENCE.md", "corpus-provenance"),
    ("README.md", "748-config readiness scan"),
)


def test_every_publication_surface_matches_results() -> None:
    d = _results()
    n_str = f"{d['distinct_configs_scanned']:,}"
    superseded = [re.compile(p) for p in _SUPERSEDED_LITERALS]

    missing_n: list[str] = []
    stale: list[str] = []
    for rel in _PUBLICATION_SURFACES:
        assert not any(rel == e or rel.startswith(e) for e in _SWEEP_EXCLUDED), rel
        text = (REPO / rel).read_text(encoding="utf-8")
        # (i) the current corpus size must appear verbatim.
        if n_str not in text:
            missing_n.append(f"{rel}: does not cite current corpus size {n_str}")
        # (ii) no superseded literal, except on an allowlisted (dated/provenance) line.
        allow = [needle for (f, needle) in _SUPERSEDED_ALLOWLIST if f == rel]
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(needle in line for needle in allow):
                continue
            for rx in superseded:
                m = rx.search(line)
                if m:
                    stale.append(f"{rel}:{lineno}: superseded token {m.group(0)!r} — {line.strip()[:90]}")

    assert not missing_n, (
        "publication surface missing the current corpus N:\n  " + "\n  ".join(missing_n)
    )
    assert not stale, (
        "superseded State-of-MCP corpus token(s) in a publication surface — the corpus "
        "refreshed and the prose must follow results.json (or add a narrow, dated "
        "allowlist entry if the number is a legitimate historical fact):\n  "
        + "\n  ".join(stale)
    )
