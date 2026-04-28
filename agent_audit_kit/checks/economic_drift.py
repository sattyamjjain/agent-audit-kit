"""Runtime economic-drift check (Project Deal class).

Pairs with AAK-PROJECT-DEAL-DRIFT-001 SAST rule. Imports cleanly from
CI test code:

    from agent_audit_kit.checks.economic_drift import assert_parity

    assert_parity(
        invocations=[
            {"model": "claude-opus-4", "price": 12.68},
            {"model": "claude-sonnet-4", "price": 10.32},
        ],
        max_drift_pct=1.5,
    )

Raises ParityDriftError if any pair of buckets deviates above
`max_drift_pct` of the mean across buckets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


class ParityDriftError(AssertionError):
    """Raised when measured drift exceeds the allowed threshold."""


@dataclass
class _Bucket:
    label: str
    mean: float
    n: int


def _bucket_stats(invocations: Sequence[dict], dimension: str, metric: str) -> list[_Bucket]:
    grouped: dict[str, list[float]] = {}
    for inv in invocations:
        key = str(inv.get(dimension, "<missing>"))
        val = float(inv.get(metric, 0.0))
        grouped.setdefault(key, []).append(val)
    return [
        _Bucket(label=label, mean=sum(vals) / len(vals), n=len(vals))
        for label, vals in grouped.items()
        if vals
    ]


def assert_parity(
    invocations: Sequence[dict],
    *,
    dimension: str = "model",
    metric: str = "price",
    max_drift_pct: float = 1.5,
) -> None:
    """Assert per-bucket means across `dimension` are within `max_drift_pct`.

    Raises ParityDriftError when violated. No-ops when only one bucket
    is present (cannot drift). The default 1.5% threshold matches the
    Project Deal experiment's 0.66% Opus-vs-Haiku deviation, leaving
    headroom for noise.
    """
    if not invocations:
        return
    buckets = _bucket_stats(invocations, dimension, metric)
    if len(buckets) < 2:
        return
    overall_mean = sum(b.mean for b in buckets) / len(buckets)
    if overall_mean == 0:
        return
    for b in buckets:
        drift_pct = abs(b.mean - overall_mean) / overall_mean * 100
        if drift_pct > max_drift_pct:
            others = [bb for bb in buckets if bb.label != b.label]
            other_means = ", ".join(f"{bb.label}={bb.mean:.4f}" for bb in others)
            raise ParityDriftError(
                f"Economic-drift on `{dimension}={b.label}`: "
                f"{metric} mean={b.mean:.4f} drifts "
                f"{drift_pct:.2f}% from overall {overall_mean:.4f} "
                f"(threshold {max_drift_pct}%). Other buckets: {other_means}"
            )
