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
    # _REGISTRY is keyed by strict_loading; seed both modes so the patch holds
    # whichever way run_scan is called.
    monkeypatch.setattr(engine, "_REGISTRY", {False: fake_registry, True: fake_registry})

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

    bad_registry = [ScannerRegistration("BadOne", broken_scan, [])]
    monkeypatch.setattr(engine, "_REGISTRY", {False: bad_registry, True: bad_registry})

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


# --- warm-registry strict_loading regression (#570) -------------------------
#
# The two strict_loading tests above both start from a cold cache, so they only
# ever exercise the first _get_registry() call. The cache used to be a single
# slot, which baked the first caller's strict_loading value in permanently: any
# lenient call — scanner_manifest(), an earlier run_scan() — left a later
# strict_loading=True caller reading the lenient registry, silently skipping a
# scanner that failed to import instead of raising. These cover the warm path.


def test_strict_loading_honoured_after_lenient_call_warmed_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lenient call first must not disarm a later strict_loading=True call."""

    monkeypatch.setattr(
        engine,
        "_OPTIONAL_SCANNERS",
        engine._OPTIONAL_SCANNERS + [("does_not_exist_xyz", "Fake", [])],
    )
    reset_registry()

    # Warm the cache in lenient mode — this is what scanner_manifest() does.
    run_scan(tmp_path, strict_loading=False)
    assert False in engine._REGISTRY

    # The strict caller must still get a strict registry build.
    with pytest.raises(ScannerLoadError) as exc_info:
        run_scan(tmp_path, strict_loading=True)
    assert "does_not_exist_xyz" in str(exc_info.value)


def test_scanner_manifest_then_strict_run_still_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact reported ordering: scanner_manifest() before a strict run."""

    monkeypatch.setattr(
        engine,
        "_OPTIONAL_SCANNERS",
        engine._OPTIONAL_SCANNERS + [("does_not_exist_xyz", "Fake", [])],
    )
    reset_registry()

    engine.scanner_manifest()
    with pytest.raises(ScannerLoadError):
        run_scan(tmp_path, strict_loading=True)


def test_lenient_still_skips_after_strict_warmed_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mirror case: a strict build must not make later lenient calls raise."""

    monkeypatch.setattr(
        engine,
        "_OPTIONAL_SCANNERS",
        engine._OPTIONAL_SCANNERS + [("does_not_exist_xyz", "Fake", [])],
    )
    reset_registry()

    with pytest.raises(ScannerLoadError):
        run_scan(tmp_path, strict_loading=True)

    # Lenient mode keeps the v0.2.x skip-the-optional behaviour.
    assert run_scan(tmp_path, strict_loading=False) is not None


def test_both_modes_are_cached_independently() -> None:
    """Each mode gets its own slot, and reset_registry() clears both."""

    reset_registry()
    assert engine._REGISTRY == {}

    lenient = engine._get_registry(strict_loading=False)
    strict = engine._get_registry(strict_loading=True)
    assert set(engine._REGISTRY) == {False, True}

    # Each mode is stable across repeated calls (still actually cached).
    assert engine._get_registry(strict_loading=False) is lenient
    assert engine._get_registry(strict_loading=True) is strict

    reset_registry()
    assert engine._REGISTRY == {}
