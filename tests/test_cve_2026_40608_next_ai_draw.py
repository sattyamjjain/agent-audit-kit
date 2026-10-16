"""CVE-2026-40608 — next-ai-draw-io < 0.4.15 body-accumulation DoS."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.scanners.transport_limits import scan


def test_vulnerable_next_ai_draw_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"next-ai-draw-io": "0.4.14"}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-NEXT-AI-DRAW-001" for f in findings)


def test_patched_next_ai_draw_pin_passes(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"next-ai-draw-io": "0.4.15"}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-NEXT-AI-DRAW-001" for f in findings)


def test_mcpframe_and_next_ai_draw_independent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"mcp-framework": "0.2.21", "next-ai-draw-io": "0.4.14"}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-MCPFRAME-001" in rule_ids
    assert "AAK-NEXT-AI-DRAW-001" in rule_ids


@pytest.mark.parametrize(("spec", "fires"), [
    ("<0.4.15", True),          # read as the fix by the first-number reader
    ("<1.0.0 >=0.4.0", True),
    (">=0.4.15 <1.0.0", False),
    ("latest", True),           # no version stated, reported as before
])
def test_next_ai_draw_range_is_judged_by_what_it_admits(tmp_path: Path, spec: str, fires: bool) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"next-ai-draw-io": spec}}), encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-NEXT-AI-DRAW-001" for f in findings) is fires
