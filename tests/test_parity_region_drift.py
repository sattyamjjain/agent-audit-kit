"""O11 — per-region drift tests + 28d baseline window for the parity
report. Builds on the v0.3.9 @aak.parity.check decorator.
"""
from __future__ import annotations

import time

import pytest

from agent_audit_kit.checks.economic_drift import ParityDriftError
from agent_audit_kit.parity import check, report, reset


@pytest.fixture(autouse=True)
def _reset_parity():
    reset()
    yield
    reset()


def test_region_drift_fires_when_per_region_means_diverge() -> None:
    """Two regions, same model, different price per region → drift."""

    @check(dimensions=["region"], metric="price")
    def quote(item: str, region: str) -> dict:
        # us-east-1 cheap, eu-west-1 expensive (cross-region tier-leak)
        return {"price": 1.0 if region == "us-east-1" else 1.45}

    for _ in range(5):
        quote("a", region="us-east-1")
        quote("b", region="eu-west-1")
    with pytest.raises(ParityDriftError):
        report(dimension="region", metric="price", max_drift_pct=1.5)


def test_region_no_drift_under_threshold_passes() -> None:
    @check(dimensions=["region"], metric="price")
    def quote(item: str, region: str) -> dict:
        return {"price": 1.0 if region == "us-east-1" else 1.005}

    for _ in range(5):
        quote("a", region="us-east-1")
        quote("b", region="eu-west-1")
    out = report(dimension="region", metric="price", max_drift_pct=2.0)
    assert out["status"] == "ok"
    assert {"us-east-1", "eu-west-1"} <= set(out["buckets"].keys())


def test_28d_baseline_window_includes_recent() -> None:
    """A 28d window includes invocations regardless of recency (synthetic)."""

    @check(dimensions=["region"], metric="price")
    def quote(item: str, region: str) -> dict:
        return {"price": 1.0 if region == "us-east-1" else 1.005}

    quote("a", region="us-east-1")
    quote("b", region="eu-west-1")
    twenty_eight_days = 28 * 24 * 3600
    out = report(
        dimension="region",
        metric="price",
        max_drift_pct=2.0,
        window_seconds=twenty_eight_days,
    )
    assert out["status"] == "ok"
    assert sum(b["n"] for b in out["buckets"].values()) == 2


def test_short_window_excludes_old_invocations() -> None:
    """A 1s window excludes everything older than 1s — useful for
    short-window noise; documented as the inverse of --baseline-window 28d."""

    @check(dimensions=["region"], metric="price")
    def quote(item: str, region: str) -> dict:
        return {"price": 1.0}

    quote("a", region="us-east-1")
    time.sleep(1.05)
    out = report(
        dimension="region",
        metric="price",
        window_seconds=0.5,
    )
    assert out["status"] == "ok"
    assert sum(b["n"] for b in out["buckets"].values()) == 0
