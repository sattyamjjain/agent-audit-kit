"""Tests for benchmarks/index_builder.py."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml


spec = importlib.util.spec_from_file_location(
    "index_builder", "benchmarks/index_builder.py"
)
assert spec is not None and spec.loader is not None
index_builder = importlib.util.module_from_spec(spec)
sys.modules["index_builder"] = index_builder  # required for @dataclass registration
spec.loader.exec_module(index_builder)


def test_score_to_grade_boundaries() -> None:
    assert index_builder.score_to_grade(100) == "A"
    assert index_builder.score_to_grade(90) == "A"
    assert index_builder.score_to_grade(89) == "B"
    assert index_builder.score_to_grade(70) == "C"
    assert index_builder.score_to_grade(0) == "F"


def test_cards_from_results(tmp_path: Path) -> None:
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            [
                {"repo": "a/good", "name": "good-server", "score": 95, "critical": 0, "high": 0, "medium": 1, "low": 0},
                {"repo": "a/bad", "name": "bad-server", "score": 40, "critical": 3, "high": 4, "medium": 2, "low": 1, "embargoed": True},
            ]
        )
    )
    cards = index_builder.cards_from_results(results)
    assert len(cards) == 2
    assert cards[0].name == "good-server"
    assert cards[0].grade == "A"
    assert cards[1].grade == "F"
    assert cards[1].disclosure_state == "embargoed"


def test_write_site_produces_index_and_cards(tmp_path: Path) -> None:
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            [{"repo": "a/clean", "name": "clean", "score": 92}]
        )
    )
    cards = index_builder.cards_from_results(results)
    site = tmp_path / "site"
    index_builder.write_site(cards, site)

    assert (site / "index.html").is_file()
    assert (site / "data" / "index.json").is_file()
    assert (site / "data" / "history.json").is_file()

    data = json.loads((site / "data" / "index.json").read_text())
    assert data[0]["grade"] == "A"
    assert (site / "server" / f"{cards[0].slug}.html").is_file()


def test_disclosure_policy_is_present() -> None:
    path = Path("docs/disclosure-policy.md")
    assert path.is_file()
    assert "90 days" in path.read_text().lower() or "90-day" in path.read_text().lower()


def test_rule_hits_extracted_from_crawler_entry(tmp_path: Path) -> None:
    import datetime as dt
    import json as _json
    results = tmp_path / "results.json"
    results.write_text(
        _json.dumps(
            {
                "crawl_timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "configs": [
                    {
                        "source_repo": "a/b",
                        "source_path": ".mcp.json",
                        "findings_by_severity": {"critical": 1, "high": 2},
                        "rule_violations": [
                            "AAK-MCP-001", "AAK-MCP-001", "AAK-MCP-005", "AAK-SSRF-001",
                        ],
                    }
                ],
            }
        )
    )
    cards = index_builder.cards_from_results(results)
    assert cards[0].rule_hits == {"AAK-MCP-001": 2, "AAK-MCP-005": 1, "AAK-SSRF-001": 1}


def _card(slug: str = "a__b", state: str = "embargoed", **kw: object) -> object:
    base: dict[str, object] = dict(
        slug=slug, name=slug.replace("__", "/"), repo_url="", grade="F", score=10,
        critical=1, high=0, medium=0, low=0,
        last_scanned="2026-10-05T00:00:00+00:00", disclosure_state=state,
    )
    base.update(kw)
    return index_builder.ServerCard(**base)


def _notice(notified: dt.date, fixed: dt.date | None = None) -> object:
    return index_builder.Notice(notified_at=notified, channel="email", fixed_at=fixed)


def _write_ledger(tmp_path: Path, notices: dict) -> Path:
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps({"_about": "test", "notices": notices}))
    return ledger


def test_first_seen_alone_never_publishes() -> None:
    # The old clock: 95 days since first_seen flipped a card to public. With no
    # notice in the ledger there is no Day 0, so it stays withheld.
    now = dt.datetime(2026, 4, 18, tzinfo=dt.timezone.utc)
    prior = {"a__b": {"slug": "a__b", "first_seen": (now - dt.timedelta(days=95)).isoformat()}}
    cards = index_builder._carry_first_seen([_card()], prior, now)
    out = index_builder._apply_disclosure(cards, {}, now)
    assert out[0].first_seen == prior["a__b"]["first_seen"]
    assert out[0].disclosure_state == "embargoed"
    assert out[0].notified_at is None and out[0].embargo_ends is None


def test_disclosure_ignores_no_findings() -> None:
    now = dt.datetime(2026, 4, 18, tzinfo=dt.timezone.utc)
    card = _card("clean", "no-findings", grade="A", score=100, critical=0)
    ledger = {"clean": _notice(dt.date(2026, 1, 1))}
    out = index_builder._apply_disclosure([card], ledger, now)
    assert out[0].disclosure_state == "no-findings"
    assert out[0].embargo_ends is None


def test_ledger_day_89_withheld_day_90_public() -> None:
    notified = dt.date(2026, 7, 1)
    ledger = {"a__b": _notice(notified)}
    day_89 = dt.datetime.combine(notified + dt.timedelta(days=89), dt.time(), dt.timezone.utc)
    day_90 = dt.datetime.combine(notified + dt.timedelta(days=90), dt.time(), dt.timezone.utc)
    held = index_builder._apply_disclosure([_card()], ledger, day_89)[0]
    assert held.disclosure_state == "embargoed"
    assert held.notified_at == "2026-07-01"
    assert held.embargo_ends == "2026-09-29"
    assert index_builder._apply_disclosure([_card()], ledger, day_90)[0].disclosure_state == "public"


def test_unnotified_card_stays_withheld_at_day_1000(tmp_path: Path) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    prior = tmp_path / "prior.json"
    prior.write_text(json.dumps([{"slug": "a__b", "first_seen": (now - dt.timedelta(days=1000)).isoformat()}]))
    site = tmp_path / "site"
    index_builder.write_site([_card(rule_hits={"AAK-MCP-001": 3})], site, prior_index=prior, ledger={})
    row = json.loads((site / "data" / "index.json").read_text())[0]
    assert row["disclosure_state"] == "embargoed"
    assert row["rule_hits"] == {}
    assert row["notified_at"] is None


def test_fixed_at_publishes_before_day_90() -> None:
    now = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
    ledger = {"a__b": _notice(dt.date(2026, 7, 1), fixed=dt.date(2026, 7, 20))}
    assert index_builder._apply_disclosure([_card()], ledger, now)[0].disclosure_state == "public"
    not_yet = {"a__b": _notice(dt.date(2026, 7, 1), fixed=dt.date(2026, 8, 5))}
    assert index_builder._apply_disclosure([_card()], not_yet, now)[0].disclosure_state == "embargoed"


def test_input_cannot_publish_around_the_ledger() -> None:
    # A flat-list entry without `embargoed` comes in as "public"; with no notice
    # it is still withheld.
    now = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
    out = index_builder._apply_disclosure([_card(state="public")], {}, now)
    assert out[0].disclosure_state == "embargoed"


def test_trend_svg_with_few_snapshots_is_a_hint() -> None:
    html = index_builder._render_trend_svg([{"snapshot": "2026-04-01", "total": 5, "distribution": {}}])
    assert "Not enough snapshots" in html


def test_trend_svg_renders_polylines() -> None:
    history = [
        {"snapshot": "2026-03-01T00:00:00", "total": 10, "distribution": {"A": 2, "B": 3, "C": 2, "D": 2, "F": 1}},
        {"snapshot": "2026-03-08T00:00:00", "total": 12, "distribution": {"A": 3, "B": 3, "C": 2, "D": 2, "F": 2}},
        {"snapshot": "2026-03-15T00:00:00", "total": 15, "distribution": {"A": 4, "B": 4, "C": 3, "D": 2, "F": 2}},
    ]
    svg = index_builder._render_trend_svg(history)
    assert svg.startswith("<svg")
    for grade in ("A", "B", "C", "D", "F"):
        assert 'stroke="#' in svg  # all 5 polylines present
    assert "2026-03-01" in svg and "2026-03-15" in svg


def test_rule_hit_section_withheld_hides_detail() -> None:
    pending = _card("x", rule_hits={"AAK-MCP-001": 2, "AAK-HOOK-001": 1})
    html = index_builder._rule_hit_section(pending)
    assert "AAK-MCP-001" not in html  # specific rules hidden while withheld
    assert " ".join(html.split()) == (
        '<p class="muted">Rule-level detail is withheld until 90 days after the '
        "maintainer is notified. Aggregate severity counts above.</p>"
    )
    notified = _card("x", rule_hits={"AAK-MCP-001": 2}, notified_at="2026-07-01", embargo_ends="2026-09-29")
    html = index_builder._rule_hit_section(notified)
    assert "AAK-MCP-001" not in html
    assert " ".join(html.split()) == (
        '<p class="muted">Rule-level detail is withheld until 2026-09-29, 90 days after '
        "the maintainer was notified. Aggregate severity counts above.</p>"
    )


def test_rule_hit_section_public_shows_detail() -> None:
    card = _card("x", "public", rule_hits={"AAK-MCP-001": 2, "AAK-HOOK-001": 1})
    html = index_builder._rule_hit_section(card)
    assert "AAK-MCP-001" in html
    assert "AAK-HOOK-001" in html
    # Rule with higher hit count appears first in the table.
    assert html.index("AAK-MCP-001") < html.index("AAK-HOOK-001")


def test_index_json_has_no_rule_ids_for_withheld_cards(tmp_path: Path) -> None:
    today = dt.datetime.now(dt.timezone.utc).date()
    results = tmp_path / "results.json"
    results.write_text(json.dumps({
        "crawl_timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "configs": [
            {"source_repo": "pub/lic", "findings_by_severity": {"critical": 1},
             "rule_violations": ["AAK-MCP-001"]},
            {"source_repo": "with/held", "findings_by_severity": {"high": 2},
             "rule_violations": ["AAK-MCP-005", "AAK-MCP-005"]},
        ],
    }))
    ledger = index_builder.load_ledger(_write_ledger(tmp_path, {
        "pub__lic": {"notified_at": (today - dt.timedelta(days=120)).isoformat(), "channel": "private-advisory"},
    }))
    site = tmp_path / "site"
    index_builder.write_site(index_builder.cards_from_results(results), site, ledger=ledger)
    rows = {r["slug"]: r for r in json.loads((site / "data" / "index.json").read_text())}
    assert rows["pub__lic"]["disclosure_state"] == "public"
    assert rows["pub__lic"]["rule_hits"] == {"AAK-MCP-001": 1}
    assert rows["with__held"]["disclosure_state"] == "embargoed"
    assert rows["with__held"]["rule_hits"] == {}
    assert rows["with__held"]["high"] == 2  # aggregate counts stay
    assert "AAK-MCP-005" not in (site / "data" / "index.json").read_text()
    assert "AAK-MCP-005" not in (site / "server" / "with__held.html").read_text()
    assert "AAK-MCP-001" in (site / "server" / "pub__lic.html").read_text()
    assert "AAK-" not in (site / "data" / "history.json").read_text()


def test_prior_index_preserves_first_seen(tmp_path: Path) -> None:
    prior = tmp_path / "prior.json"
    prior.write_text(json.dumps([{"slug": "a__b", "first_seen": "2026-08-21T07:30:00+00:00"}]))
    site = tmp_path / "site"
    index_builder.write_site([_card(), _card("new__one")], site, prior_index=prior)
    rows = {r["slug"]: r for r in json.loads((site / "data" / "index.json").read_text())}
    assert rows["a__b"]["first_seen"] == "2026-08-21T07:30:00+00:00"
    assert rows["new__one"]["first_seen"].startswith(dt.datetime.now(dt.timezone.utc).date().isoformat())


@pytest.mark.parametrize(
    "notices, message",
    [
        ({"a__b": {"notified_at": "2026-07-01", "channel": "carrier-pigeon"}}, "channel"),
        ({"a__b": {"notified_at": "07/01/2026", "channel": "email"}}, "YYYY-MM-DD"),
        ({"a__b": {"notified_at": "2026-02-30", "channel": "email"}}, "notified_at"),
        ({"a__b": {"notified_at": "2026-07-01", "channel": "email", "rule_ids": ["AAK-MCP-001"]}}, "unknown key"),
        ({"a__b": {"channel": "email"}}, "missing 'notified_at'"),
        ({"a__b": {"notified_at": "2999-01-01", "channel": "email"}}, "future"),
        ({"owner/repo": {"notified_at": "2026-07-01", "channel": "email"}}, "not an index slug"),
        ({"a__b": {"notified_at": "2026-07-01", "channel": "email", "fixed_at": "2026-06-01"}}, "before notified_at"),
        ({"a__b": {"notified_at": "2026-07-01", "channel": "email", "reminders": ["2026-06-30"]}}, "before notified_at"),
    ],
)
def test_ledger_validation_fails_loudly(tmp_path: Path, notices: dict, message: str) -> None:
    with pytest.raises(index_builder.LedgerError, match=message):
        index_builder.load_ledger(_write_ledger(tmp_path, notices), today=dt.date(2026, 10, 10))


def test_ledger_top_level_and_missing_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"_about": "x", "notices": {}, "extra": 1}))
    with pytest.raises(index_builder.LedgerError, match="top-level"):
        index_builder.load_ledger(bad)
    with pytest.raises(index_builder.LedgerError, match="cannot read"):
        index_builder.load_ledger(tmp_path / "missing.json")
    assert index_builder.load_ledger(None) == {}


def test_shipped_ledger_is_valid_and_carries_nothing_private() -> None:
    shipped = Path("benchmarks/disclosure_ledger.json")
    index_builder.load_ledger(shipped)  # raises if malformed
    notices = json.dumps(json.loads(shipped.read_text())["notices"])
    for forbidden in ("AAK-", "@", "http"):
        assert forbidden not in notices, f"public ledger must not hold {forbidden!r}"


def test_republish_sanitizes_without_snapshot_or_new_publication(tmp_path: Path) -> None:
    today = dt.datetime.now(dt.timezone.utc).date()
    published = tmp_path / "index.json"
    published.write_text(json.dumps([
        # What gh-pages served before the fix: rule ids on a withheld card.
        {**vars(_card("leak__y")), "rule_hits": {"AAK-MCP-001": 4}},
        {**vars(_card("was__public", "public")), "rule_hits": {"AAK-HOOK-001": 1}},
        # Came due since the last snapshot, but the published file has no rule
        # detail for it, so a re-render must not publish it.
        vars(_card("came__due")),
    ]))
    history = tmp_path / "history.json"
    history.write_text(json.dumps([{"snapshot": "2026-10-05T16:08:07+00:00", "total": 3, "distribution": {}}]))
    due = (today - dt.timedelta(days=100)).isoformat()
    ledger = _write_ledger(tmp_path, {
        "was__public": {"notified_at": due, "channel": "email"},
        "came__due": {"notified_at": due, "channel": "email"},
    })
    site = tmp_path / "site"
    rc = index_builder.main([
        "--from-index", str(published), "--history", str(history),
        "--ledger", str(ledger), "--site-dir", str(site), "--clean",
    ])
    assert rc == 0
    rows = {r["slug"]: r for r in json.loads((site / "data" / "index.json").read_text())}
    assert rows["leak__y"]["rule_hits"] == {}
    assert rows["was__public"]["disclosure_state"] == "public"
    assert rows["was__public"]["rule_hits"] == {"AAK-HOOK-001": 1}
    assert rows["came__due"]["disclosure_state"] == "embargoed"
    assert len(json.loads((site / "data" / "history.json").read_text())) == 1  # no new snapshot
    assert "Snapshot: 2026-10-05T16:08+00:00." in (site / "index.html").read_text()


def test_republish_missing_index_is_a_noop(tmp_path: Path) -> None:
    site = tmp_path / "site"
    assert index_builder.main(["--from-index", str(tmp_path / "none.json"), "--site-dir", str(site)]) == 0
    assert not site.exists()


def test_workflow_uses_the_ledger_on_every_deploy_path() -> None:
    wf = yaml.safe_load(Path(".github/workflows/mcp-security-index.yml").read_text())
    steps = {s.get("name"): s for s in wf["jobs"]["snapshot"]["steps"]}
    build = steps["Build MCP Security Index site"]
    assert build["if"] == "github.event_name != 'push'"
    assert "--ledger benchmarks/disclosure_ledger.json" in build["run"]
    assert "--prior-index pages_staging/data/index.json" in build["run"]
    rerender = steps["Re-render the published index (no crawl, no snapshot)"]
    assert rerender["if"] == "github.event_name == 'push'"
    assert "--from-index pages_staging/data/index.json" in rerender["run"]
    assert "--ledger benchmarks/disclosure_ledger.json" in rerender["run"]
    stage = steps["Stage payload"]["run"]
    assert stage.index("rm -rf pages_staging/server") < stage.index("cp -r benchmarks/site/. pages_staging/")
    # PyYAML reads the bare `on` key as True.
    push_paths = (wf.get("on") or wf.get(True))["push"]["paths"]
    assert "benchmarks/disclosure_ledger.json" in push_paths
    assert "benchmarks/index_builder.py" in push_paths
