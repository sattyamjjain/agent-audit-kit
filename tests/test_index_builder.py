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
