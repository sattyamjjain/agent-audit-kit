#!/usr/bin/env python3
"""Wilson score interval for a binomial proportion — stdlib only.

No new runtime dependency: the FP-rate benchmark needs a confidence interval on
a small-n proportion, and the Wilson score interval is the right tool for small
n (unlike the normal approximation, it stays inside [0, 1] and does not collapse
to a zero-width interval at k=0 or k=n).
"""

from __future__ import annotations

import math


def wilson_interval(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """95% Wilson score interval for ``k`` successes out of ``n`` trials.

    ``z`` defaults to the 97.5th percentile of the standard normal (two-sided
    95%). Returns ``(low, high)`` clamped to ``[0, 1]``. ``n == 0`` → ``(0, 0)``.
    """
    if n <= 0:
        return (0.0, 0.0)
    if k < 0 or k > n:
        raise ValueError(f"k={k} out of range for n={n}")
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def pct(x: float, digits: int = 1) -> str:
    return f"{100 * x:.{digits}f}%"
