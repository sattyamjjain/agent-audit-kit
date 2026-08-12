"""Tests for the `aak watch-cve` NVD feed (agent_audit_kit.feeds).

Exactly one feed is live (nvd, the NVD 2.0 API). Its network call is opt-in behind
`--online` / `run_watch(online=True)`; every test here runs offline. Covers: parsing
a committed NVD 2.0 response, the mixed implemented/stub exit code, and that no
network call happens without the flag.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit import feeds

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nvd" / "nvd_2_0_mcp_sample.json"


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path, monkeypatch):
    """Keep every test off the real ~/.agent-audit-kit and off the network."""
    monkeypatch.setattr(feeds, "_STATE_DIR", tmp_path)
    monkeypatch.setattr(feeds, "_STATE_FILE", tmp_path / "watch-state.json")
    monkeypatch.setenv("AAK_NVD_CACHE", str(tmp_path / "nvd-cache.json"))
    monkeypatch.setattr(feeds, "_ONLINE", False)


def test_parse_nvd_fixture_offline() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    entries = feeds._parse_nvd(payload)
    assert [e["cve_id"] for e in entries] == ["CVE-2026-19516", "CVE-2026-19337"]
    grafana = entries[0]
    assert grafana["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-19516"
    assert "X-Grafana-URL" in grafana["title"]      # English description, not Spanish
    assert grafana["published"] == "2026-08-11T06:17:13.433"


def test_parse_nvd_tolerates_missing_fields() -> None:
    assert feeds._parse_nvd({}) == []
    assert feeds._parse_nvd({"vulnerabilities": [{"cve": {}}, {}]}) == []


def test_mixed_implemented_and_stub_exits_zero(capsys) -> None:
    # nvd (live, offline cache read) + ox (stub) -> at least one live feed worked -> 0.
    rc = feeds.run_watch(
        feed_ids=["nvd", "ox"], emit=None, interval_seconds=1,
        max_iterations=1, dry_run=True, online=False,
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "feed ox: not implemented" in err
    assert "nvd" in err  # the message names the live feed


def test_all_stub_exits_nonzero() -> None:
    rc = feeds.run_watch(
        feed_ids=["ox", "cert-cc"], emit=None, interval_seconds=1,
        max_iterations=1, dry_run=True, online=False,
    )
    assert rc == 2


def test_no_network_call_without_online_flag(monkeypatch) -> None:
    import urllib.request

    called = {"hit": False}

    def _boom(*a, **k):  # pragma: no cover - must never run
        called["hit"] = True
        raise AssertionError("network call made without --online")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    rc = feeds.run_watch(
        feed_ids=["nvd"], emit=None, interval_seconds=1,
        max_iterations=1, dry_run=True, online=False,
    )
    assert rc == 0
    assert called["hit"] is False


def test_online_flag_reaches_the_network_layer(monkeypatch, tmp_path) -> None:
    # With online=True the nvd fetcher DOES call urlopen; stub the transport so the
    # test stays offline but proves the flag flips the behaviour and the cache is written.
    import io
    import urllib.request

    payload = FIXTURE.read_bytes()

    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): self.close()

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp(payload))
    monkeypatch.setattr(feeds, "_ONLINE", True)
    got = feeds._nvd_fetcher("nvd")
    assert [e["cve_id"] for e in got] == ["CVE-2026-19516", "CVE-2026-19337"]
    # cache was written by the online fetch and is readable offline afterwards
    monkeypatch.setattr(feeds, "_ONLINE", False)
    assert [e["cve_id"] for e in feeds._nvd_fetcher("nvd")] == ["CVE-2026-19516", "CVE-2026-19337"]
