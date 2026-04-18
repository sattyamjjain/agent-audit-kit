"""Tests for benchmarks/index_builder.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


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


def test_embargo_transition_flips_after_90_days(tmp_path: Path) -> None:
    import datetime as dt
    now = dt.datetime(2026, 4, 18, tzinfo=dt.timezone.utc)
    prior = {
        "a__b": {"slug": "a__b", "first_seen": (now - dt.timedelta(days=95)).isoformat()},
        "c__d": {"slug": "c__d", "first_seen": (now - dt.timedelta(days=30)).isoformat()},
    }
    cards = [
        index_builder.ServerCard(
            slug="a__b", name="a/b", repo_url="", grade="F", score=10,
            critical=1, high=0, medium=0, low=0,
            last_scanned=now.isoformat(), disclosure_state="embargoed",
        ),
        index_builder.ServerCard(
            slug="c__d", name="c/d", repo_url="", grade="F", score=10,
            critical=1, high=0, medium=0, low=0,
            last_scanned=now.isoformat(), disclosure_state="embargoed",
        ),
    ]
    out = index_builder._apply_embargo_transitions(cards, prior, now)
    states = {c.slug: c.disclosure_state for c in out}
    assert states["a__b"] == "public"  # 95 days > 90
    assert states["c__d"] == "embargoed"  # 30 days < 90


def test_embargo_transition_ignores_no_findings(tmp_path: Path) -> None:
    import datetime as dt
    now = dt.datetime(2026, 4, 18, tzinfo=dt.timezone.utc)
    card = index_builder.ServerCard(
        slug="clean", name="clean", repo_url="", grade="A", score=100,
        critical=0, high=0, medium=0, low=0,
        last_scanned=now.isoformat(), disclosure_state="no-findings",
    )
    out = index_builder._apply_embargo_transitions([card], {}, now)
    assert out[0].disclosure_state == "no-findings"  # unchanged


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


def test_rule_hit_section_embargoed_hides_detail() -> None:
    import datetime as dt
    card = index_builder.ServerCard(
        slug="x", name="x", repo_url="", grade="F", score=10,
        critical=1, high=0, medium=0, low=0,
        last_scanned="2026-04-18",
        disclosure_state="embargoed",
        rule_hits={"AAK-MCP-001": 2, "AAK-HOOK-001": 1},
        first_seen="2026-04-01T00:00:00+00:00",
    )
    html = index_builder._rule_hit_section(card, dt.datetime(2026, 4, 18, tzinfo=dt.timezone.utc))
    assert "AAK-MCP-001" not in html  # specific rules hidden under embargo
    assert "embargoed" in html.lower() or "embargo" in html.lower()


def test_rule_hit_section_public_shows_detail() -> None:
    import datetime as dt
    card = index_builder.ServerCard(
        slug="x", name="x", repo_url="", grade="F", score=10,
        critical=1, high=0, medium=0, low=0,
        last_scanned="2026-04-18",
        disclosure_state="public",
        rule_hits={"AAK-MCP-001": 2, "AAK-HOOK-001": 1},
    )
    html = index_builder._rule_hit_section(card, dt.datetime(2026, 4, 18, tzinfo=dt.timezone.utc))
    assert "AAK-MCP-001" in html
    assert "AAK-HOOK-001" in html
    # Rule with higher hit count appears first in the table.
    assert html.index("AAK-MCP-001") < html.index("AAK-HOOK-001")
