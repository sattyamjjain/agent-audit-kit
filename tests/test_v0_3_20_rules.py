"""v0.3.20 — watcher dedup fix (#163) + Metis POMDP detectors
(AAK-METIS-REFUSAL-REFEED-001 + AAK-METIS-SCORING-SINK-001)."""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.metis_pomdp import scan as metis_scan

FIXTURES = Path(__file__).parent / "fixtures" / "metis_pomdp"
REFUSAL = "AAK-METIS-REFUSAL-REFEED-001"
SCORING = "AAK-METIS-SCORING-SINK-001"


def test_refusal_refeed_unsafe_fires(tmp_path: Path) -> None:
    """`handle_refusal(text) -> text` + `messages.append(refusal)` both fire."""
    shutil.copy(FIXTURES / "refusal_refeed_unsafe.py", tmp_path / "x.py")
    findings, _ = metis_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == REFUSAL]
    assert len(fires) >= 1
    for f in fires:
        assert f.severity.name == "MEDIUM"


def test_refusal_categorized_passes(tmp_path: Path) -> None:
    """Function that discretizes refusal into an enum must NOT fire."""
    shutil.copy(FIXTURES / "refusal_refeed_safe.py", tmp_path / "x.py")
    findings, _ = metis_scan(tmp_path)
    assert not any(f.rule_id == REFUSAL for f in findings)


def test_scoring_sink_unsafe_fires(tmp_path: Path) -> None:
    """`messages.append(score-tainted critique)` must fire."""
    shutil.copy(FIXTURES / "scoring_sink_unsafe.py", tmp_path / "x.py")
    findings, _ = metis_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == SCORING]
    assert len(fires) >= 1


def test_no_metis_hints_passes(tmp_path: Path) -> None:
    """File with no refusal/scoring token must early-exit cleanly."""
    (tmp_path / "x.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )
    findings, _ = metis_scan(tmp_path)
    assert findings == []
