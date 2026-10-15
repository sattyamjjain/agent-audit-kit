"""The parity decorator check reads a long decorator in linear time.

`_PARITY_DECORATOR_RE` runs on the source of each decorator of a pricing
function. Its optional dotted prefix, `(?:[\\w.]+\\.)?`, started at every `.`
of a dotted name and read to its end, so a long one took the square of its
length: 40,000 characters took 2.4 seconds. The prefix never decided a match,
since the `.` before `parity` is the `\\W` that opens one.
"""

from __future__ import annotations

import time

import pytest

from agent_audit_kit.scanners.project_deal_drift import _PARITY_DECORATOR_RE


@pytest.mark.parametrize(("decorator", "parity"), [
    ("parity.check", True),
    ("aak.parity.check(x)", True),
    ("x.y.parity . check", True),
    ("parity_check", True),
    ("disparity", False),
    ("a.parity", True),
    ("parityx", False),
])
def test_parity_decorator_keeps_its_shape(decorator: str, parity: bool) -> None:
    assert bool(_PARITY_DECORATOR_RE.search(decorator)) is parity


def test_a_long_dotted_decorator_reads_in_linear_time() -> None:
    """1 MB of `a.`. The bound is loose for slow CI runners."""
    started = time.perf_counter()
    _PARITY_DECORATOR_RE.search("a." * 500_000)
    assert time.perf_counter() - started < 5.0
