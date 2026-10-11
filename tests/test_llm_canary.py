"""The weekly --llm-scan canary fails on every breakage it exists to catch.

scripts/llm_canary.py only runs against the live API on a schedule, so its
pass/fail logic is pinned here offline with a scripted provider.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from agent_audit_kit import llm_scan
from agent_audit_kit.llm_scan import LlmCallError, LlmVerdict, ToolText, run_llm_scan

REPO = Path(__file__).resolve().parent.parent
FIXTURE = REPO / "tests" / "fixtures" / "llm_canary"

_spec = importlib.util.spec_from_file_location("llm_canary", REPO / "scripts" / "llm_canary.py")
assert _spec and _spec.loader
canary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(canary)

LABELS = json.loads((FIXTURE / "labels.json").read_text())


def test_fixture_and_labels_agree() -> None:
    tools = json.loads((FIXTURE / ".mcp.json").read_text())["mcpServers"]["canary"]["tools"]
    names = [t["name"] for t in tools]
    assert len(LABELS["poisoned"]) == 5 and len(LABELS["benign"]) == 5
    assert sorted(names) == sorted(LABELS["poisoned"] + LABELS["benign"])
    assert {t.name for t in llm_scan.collect_tool_texts(FIXTURE)} == set(names)


def _run(monkeypatch: pytest.MonkeyPatch, flag: set[str], served: str = "claude-haiku-5-5",
         raise_for: frozenset[str] = frozenset()) -> llm_scan.LlmScanReport:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    def fake(model: str, tool: ToolText) -> LlmVerdict:
        if tool.name in raise_for:
            raise LlmCallError("HTTP 500: overloaded", status=500)
        status = "flagged" if tool.name in flag else "clean"
        return LlmVerdict(status, reason="r", served_model=served)

    monkeypatch.setattr(llm_scan, "_call_anthropic", fake)
    return run_llm_scan(FIXTURE, model="claude-haiku-5-5")


def test_passes_when_the_model_does_its_job(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, flag=set(LABELS["poisoned"]))
    assert canary.check(report, LABELS, min_caught=4, max_false=1) == []


def test_fails_when_recall_drops(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, flag=set(LABELS["poisoned"][:3]))
    problems = canary.check(report, LABELS, min_caught=4, max_false=1)
    assert any("caught 3/5" in p for p in problems)


def test_fails_when_benign_tools_are_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, flag=set(LABELS["poisoned"]) | set(LABELS["benign"][:2]))
    problems = canary.check(report, LABELS, min_caught=4, max_false=1)
    assert any("flagged 2 benign" in p for p in problems)


def test_fails_when_another_model_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, flag=set(LABELS["poisoned"]), served="claude-haiku-4-5")
    problems = canary.check(report, LABELS, min_caught=4, max_false=1)
    assert any("replies came from" in p for p in problems)


def test_fails_when_a_tool_goes_unanalyzed(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, flag=set(LABELS["poisoned"]), raise_for={"translate"})
    problems = canary.check(report, LABELS, min_caught=4, max_false=1)
    assert any(p.startswith("translate not analyzed") for p in problems)


def test_main_exits_nonzero_without_a_key(monkeypatch: pytest.MonkeyPatch,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert canary.main(["--model", "claude-haiku-5-5"]) == 1
    assert "ANTHROPIC_API_KEY is not set" in capsys.readouterr().out
