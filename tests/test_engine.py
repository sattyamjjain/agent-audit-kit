"""Tests for `agent_audit_kit.engine.run_scan`.

Covers:
- Scanner crash resilience (Phase 1, item 2): a scanner that raises does
  not abort the whole scan; it emits a `AAK-INTERNAL-SCANNER-FAIL` INFO
  finding and the remaining scanners still run.
- `--strict-loading` behavior (Phase 1, item 4): when an optional scanner
  module fails to import, strict mode raises `ScannerLoadError`.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit import engine
from agent_audit_kit.engine import (
    ScannerLoadError,
    ScannerRegistration,
    reset_registry,
    run_scan,
)
from agent_audit_kit.models import Finding


@pytest.fixture(autouse=True)
def _reset_registry_between_tests() -> Iterator[None]:
    reset_registry()
    yield
    reset_registry()


def test_run_scan_survives_scanner_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A scanner that raises must not abort the scan."""

    def broken_scan(**kwargs: Any) -> tuple[list[Finding], set[str]]:
        del kwargs
        raise RuntimeError("boom")

    def healthy_scan(**kwargs: Any) -> tuple[list[Finding], set[str]]:
        del kwargs
        return [], set()

    fake_registry = [
        ScannerRegistration("BrokenScanner", broken_scan, []),
        ScannerRegistration("HealthyScanner", healthy_scan, []),
    ]
    monkeypatch.setattr(engine, "_REGISTRY", fake_registry)

    result = run_scan(tmp_path)
    ids = [f.rule_id for f in result.findings]
    assert "AAK-INTERNAL-SCANNER-FAIL" in ids
    crash = next(f for f in result.findings if f.rule_id == "AAK-INTERNAL-SCANNER-FAIL")
    assert "BrokenScanner" in crash.evidence
    assert "RuntimeError" in crash.evidence


def test_internal_fail_finding_not_suppressed_by_rule_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The crash signal must survive --rules=<narrow list>; users cannot accidentally silence it."""

    def broken_scan(**kwargs: Any) -> tuple[list[Finding], set[str]]:
        del kwargs
        raise ValueError("nope")

    monkeypatch.setattr(engine, "_REGISTRY", [ScannerRegistration("BadOne", broken_scan, [])])

    result = run_scan(tmp_path, rules=["AAK-MCP-001"])
    ids = [f.rule_id for f in result.findings]
    assert "AAK-INTERNAL-SCANNER-FAIL" in ids


def test_strict_loading_raises_on_missing_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With strict_loading=True, an ImportError during registry build surfaces as ScannerLoadError."""

    original_optional = engine._OPTIONAL_SCANNERS
    monkeypatch.setattr(
        engine,
        "_OPTIONAL_SCANNERS",
        original_optional + [("does_not_exist_xyz", "Fake", [])],
    )
    reset_registry()
    with pytest.raises(ScannerLoadError) as exc_info:
        run_scan(tmp_path, strict_loading=True)
    assert "does_not_exist_xyz" in str(exc_info.value)


def test_default_loading_silently_skips_missing_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default mode (strict_loading=False) keeps the v0.2.x behavior of skipping missing optionals."""

    original_optional = engine._OPTIONAL_SCANNERS
    monkeypatch.setattr(
        engine,
        "_OPTIONAL_SCANNERS",
        original_optional + [("does_not_exist_xyz", "Fake", [])],
    )
    reset_registry()
    result = run_scan(tmp_path, strict_loading=False)
    assert result is not None


def test_registry_includes_pin_drift_scanner() -> None:
    """Phase 1 item 1 regression guard: pin_drift must be registered."""

    reset_registry()
    names = [r.name for r in engine._get_registry()]
    assert "Pin drift" in names
