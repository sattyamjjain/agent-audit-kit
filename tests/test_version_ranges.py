"""Tests for scanners/_versions.py: what a version specifier admits.

The pin table used to read a specifier's first number, so an upper bound read as
the version. These cases pin down the three grammars the table now reads, and the
property the table relies on: a range is judged by the versions it admits,
whatever order its bounds are written in.
"""

from __future__ import annotations

import time

import pytest

from agent_audit_kit.scanners._versions import (
    TOP,
    admits,
    exact_version,
    is_exact_version,
    parse_range,
    parse_version,
)


@pytest.mark.parametrize(("spec", "dialect", "expected"), [
    # npm: caret, tilde, x-ranges, hyphen ranges, unions.
    ("^1.2.3", "npm", [((1, 2, 3), (2, 0, 0))]),
    ("^0.2.3", "npm", [((0, 2, 3), (0, 3, 0))]),
    ("^0.0.3", "npm", [((0, 0, 3), (0, 0, 4))]),
    ("^0", "npm", [((0, 0, 0), (1, 0, 0))]),
    ("~1.2.3", "npm", [((1, 2, 3), (1, 3, 0))]),
    ("~1", "npm", [((1, 0, 0), (2, 0, 0))]),
    ("1.2", "npm", [((1, 2, 0), (1, 3, 0))]),          # an x-range, not 1.2.0
    ("1.x", "npm", [((1, 0, 0), (2, 0, 0))]),
    ("1.2.3", "npm", [((1, 2, 3), (1, 2, 4))]),
    (">1.2", "npm", [((1, 3, 0), TOP)]),
    ("<=1.2", "npm", [((0, 0, 0), (1, 3, 0))]),
    ("<3.1.3", "npm", [((0, 0, 0), (3, 1, 3))]),
    ("1.2.3 - 2.3.4", "npm", [((1, 2, 3), (2, 3, 5))]),
    (">=1.0.0 <2.0.0 || >=3.0.0", "npm", [((1, 0, 0), (2, 0, 0)), ((3, 0, 0), TOP)]),
    (">= 1.2.3", "npm", [((1, 2, 3), TOP)]),
    ("16.4.0-canary.12", "npm", [((16, 4, 0), (16, 4, 1))]),   # a pre-release folds
    # Poetry: a bare version is exact, `*` widens it.
    ("^1.90.0", "poetry", [((1, 90, 0), (2, 0, 0))]),
    ("1.2", "poetry", [((1, 2, 0), (1, 2, 1))]),
    ("1.2.*", "poetry", [((1, 2, 0), (1, 3, 0))]),
    (">=1.2,<2.0", "poetry", [((1, 2, 0), (2, 0, 0))]),
    ("^1.0 || ^2.0", "poetry", [((1, 0, 0), (3, 0, 0))]),
    # PEP 440: zero-padding, wildcards, compatible release, exclusions.
    ("==1.90.0", "pep440", [((1, 90, 0), (1, 90, 1))]),
    ("==1.2", "pep440", [((1, 2, 0), (1, 2, 1))]),
    ("==1.2.*", "pep440", [((1, 2, 0), (1, 3, 0))]),
    ("~=1.2", "pep440", [((1, 2, 0), (2, 0, 0))]),
    ("~=1.2.3", "pep440", [((1, 2, 3), (1, 3, 0))]),
    (">1.2", "pep440", [((1, 2, 1), TOP)]),
    ("!=1.83.0", "pep440", [((0, 0, 0), (1, 83, 0)), ((1, 83, 1), TOP)]),
    ("1!2.0", "pep440", [((2, 0, 0), (2, 0, 1))]),
])
def test_specifier_admits(spec: str, dialect: str, expected: list) -> None:
    assert list(parse_range(spec, dialect) or ()) == expected


def test_bound_order_does_not_change_a_range() -> None:
    """`<2.0.0,>=1.0.0` read as 2.0.0 and `>=1.0.0,<2.0.0` as 1.0.0."""
    assert parse_range("<2.0.0,>=1.0.0", "pep440") == parse_range(">=1.0.0,<2.0.0", "pep440")
    assert parse_range("<2.0.0 >=1.0.0", "npm") == parse_range(">=1.0.0 <2.0.0", "npm")


def test_an_upper_bound_admits_everything_below_it() -> None:
    """`litellm<1.84.0` read as 1.84.0, the fixed release, though it admits none."""
    spans = parse_range("<1.84.0", "pep440")
    assert spans is not None
    assert admits(spans, (0, 0, 0), (1, 84, 0))
    assert not admits(spans, (1, 84, 0), TOP)


@pytest.mark.parametrize(("spec", "dialect"), [
    ("", "npm"), ("*", "npm"), ("latest", "npm"), ("canary", "npm"),
    ("workspace:^1.0.0", "npm"), ("file:../x", "npm"), ("github:o/r#abc1234", "npm"),
    ("1..2", "npm"), ("v", "npm"), ("1.2.3-", "npm"),
    ("^1.0", "pep440"),          # not PEP 440
    ("1.0 || 2.0", "pep440"),    # PEP 440 has no "or"
])
def test_no_readable_version(spec: str, dialect: str) -> None:
    assert parse_range(spec, dialect) is None


def test_a_contradiction_admits_nothing() -> None:
    assert parse_range(">=2.0.0,<1.0.0", "pep440") == ()


def test_exact_versions() -> None:
    assert exact_version(parse_range("==1.2.3", "pep440") or ()) == (1, 2, 3)
    assert exact_version(parse_range("^1.2.3", "npm") or ()) is None
    assert parse_version("1.2") == (1, 2, 0)
    assert parse_version("1.x") is None
    assert is_exact_version("1.2.3-beta.1")
    assert not is_exact_version("1.2")


def test_a_crafted_specifier_parses_in_linear_time() -> None:
    """The reader is a hand-written scanner, so no input backtracks."""
    start = time.perf_counter()
    for spec in ("1." + "a" * 200_000 + "!", " " * 200_000 + "-" + " " * 200_000, ">=" * 100_000):
        parse_range(spec, "npm")
        parse_range(spec, "pep440")
    assert time.perf_counter() - start < 2.0
