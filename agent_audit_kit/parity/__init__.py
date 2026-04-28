"""F2 — runtime parity-check decorator + report.

    from agent_audit_kit.parity import check, report

    @check(dimensions=["model"], metric="price")
    def quote(item, model):
        ...

The decorator records every invocation's `(dimensions, metric)`
tuples and raises `ParityDriftError` when a per-bucket mean drifts
above `max_drift_pct` (default 1.5%) of the overall mean.

CLI: `agent-audit-kit parity report --window 7d` (registered in cli.py).
"""

from __future__ import annotations

import functools
import inspect
import threading
import time
from collections import defaultdict
from typing import Any, Callable

from agent_audit_kit.checks.economic_drift import ParityDriftError, assert_parity


_lock = threading.Lock()
_invocations: list[dict] = []


def check(
    *,
    dimensions: list[str],
    metric: str,
    max_drift_pct: float = 1.5,
    fail_at_call: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: record `(dimensions[*], metric)` for each call.

    `fail_at_call=True` runs `assert_parity` synchronously after each
    invocation (CI-style). Default is to record only and let
    `parity report` (CLI) or test fixtures call assert_parity.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            result = fn(*args, **kwargs)
            record: dict[str, Any] = {"_ts": time.time()}
            for d in dimensions:
                if d in bound.arguments:
                    record[d] = bound.arguments[d]
            # Metric resolution: returned dict's `metric` key, or the
            # whole return if numeric, or kwargs[metric].
            if isinstance(result, dict) and metric in result:
                record[metric] = float(result[metric])
            elif isinstance(result, (int, float)):
                record[metric] = float(result)
            elif metric in bound.arguments:
                try:
                    record[metric] = float(bound.arguments[metric])
                except (TypeError, ValueError):
                    pass
            with _lock:
                _invocations.append(record)
            if fail_at_call and len(_invocations) >= 2 and dimensions:
                assert_parity(
                    list(_invocations),
                    dimension=dimensions[0],
                    metric=metric,
                    max_drift_pct=max_drift_pct,
                )
            return result

        return wrapper

    return decorator


def get_invocations() -> list[dict]:
    """Return a copy of the recorded invocations (test helper)."""
    with _lock:
        return list(_invocations)


def reset() -> None:
    """Clear the recorded invocations (test helper)."""
    with _lock:
        _invocations.clear()


def report(
    *,
    dimension: str = "model",
    metric: str = "price",
    window_seconds: float | None = None,
    max_drift_pct: float = 1.5,
) -> dict:
    """Compute summary stats + run the parity assertion.

    Returns a dict suitable for JSON dumping; raises ParityDriftError
    if the assertion fails (caller decides what to do).
    """
    with _lock:
        invs = list(_invocations)
    if window_seconds is not None:
        cutoff = time.time() - window_seconds
        invs = [i for i in invs if i.get("_ts", 0) >= cutoff]
    grouped: dict[str, list[float]] = defaultdict(list)
    for inv in invs:
        if metric in inv and dimension in inv:
            grouped[str(inv[dimension])].append(float(inv[metric]))
    summary = {
        label: {"n": len(v), "mean": (sum(v) / len(v)) if v else 0.0}
        for label, v in grouped.items()
    }
    out = {
        "dimension": dimension,
        "metric": metric,
        "window_seconds": window_seconds,
        "buckets": summary,
        "max_drift_pct": max_drift_pct,
    }
    if len(grouped) >= 2:
        assert_parity(
            [{dimension: lab, metric: m} for lab, vs in grouped.items() for m in vs],
            dimension=dimension,
            metric=metric,
            max_drift_pct=max_drift_pct,
        )
    out["status"] = "ok"
    return out


__all__ = ["check", "get_invocations", "reset", "report", "ParityDriftError"]
