"""Tests for the v0.3.9 runtime helpers (parity decorator, sanitiser,
checks.economic_drift, autofix codemod)."""
from __future__ import annotations

import pytest

from agent_audit_kit.checks.economic_drift import (
    ParityDriftError,
    assert_parity,
)
from agent_audit_kit.parity import check, get_invocations, report, reset
from agent_audit_kit.sanitizers.deepseek import sanitize_tool_description


@pytest.fixture(autouse=True)
def _reset_parity():
    reset()
    yield
    reset()


# -------------------- assert_parity --------------------

def test_assert_parity_within_threshold_passes() -> None:
    invs = [
        {"model": "opus", "price": 1.00},
        {"model": "opus", "price": 1.01},
        {"model": "haiku", "price": 1.00},
        {"model": "haiku", "price": 1.01},
    ]
    assert_parity(invs, dimension="model", metric="price", max_drift_pct=2.0)


def test_assert_parity_drift_raises() -> None:
    invs = [
        {"model": "opus", "price": 10.00},
        {"model": "opus", "price": 10.01},
        {"model": "haiku", "price": 7.00},
        {"model": "haiku", "price": 7.01},
    ]
    with pytest.raises(ParityDriftError):
        assert_parity(
            invs, dimension="model", metric="price", max_drift_pct=1.5
        )


# -------------------- @parity.check decorator --------------------

def test_parity_check_records_invocations() -> None:
    @check(dimensions=["model"], metric="price")
    def quote(item: str, model: str) -> dict:
        return {"price": 1.0 if model == "opus" else 1.01}

    quote("a", model="opus")
    quote("b", model="haiku")
    invs = get_invocations()
    assert len(invs) == 2
    assert {i["model"] for i in invs} == {"opus", "haiku"}


def test_parity_report_detects_drift() -> None:
    @check(dimensions=["model"], metric="price")
    def quote(item: str, model: str) -> dict:
        return {"price": 10.0 if model == "opus" else 7.0}

    for _ in range(3):
        quote("x", model="opus")
        quote("x", model="haiku")
    with pytest.raises(ParityDriftError):
        report(dimension="model", metric="price", max_drift_pct=1.5)


def test_parity_report_under_threshold_returns_ok() -> None:
    @check(dimensions=["model"], metric="price")
    def quote(item: str, model: str) -> dict:
        return {"price": 1.0 if model == "opus" else 1.005}

    for _ in range(3):
        quote("x", model="opus")
        quote("x", model="haiku")
    out = report(dimension="model", metric="price", max_drift_pct=2.0)
    assert out["status"] == "ok"
    assert "opus" in out["buckets"]
    assert "haiku" in out["buckets"]


# -------------------- sanitize_tool_description --------------------

def test_sanitize_strips_route_token() -> None:
    text = "search docs [ROUTE: privileged_expert]"
    cleaned = sanitize_tool_description(text)
    assert "ROUTE:" not in cleaned
    assert "[REDACTED]" in cleaned


def test_sanitize_strips_control_chars() -> None:
    text = "normal\x00\x07description"
    cleaned = sanitize_tool_description(text)
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned


def test_sanitize_truncates_oversize() -> None:
    text = "x" * 5000
    cleaned = sanitize_tool_description(text, max_length=128)
    assert len(cleaned) <= 128 + len("...[truncated]")


def test_sanitize_idempotent() -> None:
    text = "tool description [ROUTE: x] more"
    once = sanitize_tool_description(text)
    twice = sanitize_tool_description(once)
    assert once == twice


def test_sanitize_empty_input() -> None:
    assert sanitize_tool_description("") == ""
