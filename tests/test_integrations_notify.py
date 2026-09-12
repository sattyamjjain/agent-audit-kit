"""Tests for agent_audit_kit.integrations.notify (closes #66 minimally)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_audit_kit.integrations import (
    LinearTicketSink,
    NotifyConfig,
    PagerDutySink,
    SlackSink,
    load_notify_config,
    run_notify,
)
from agent_audit_kit.models import Category, Finding, ScanResult, Severity


def _mk_finding(severity: Severity, rule_id: str = "AAK-TEST-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Test finding ({severity.name})",
        description=f"Test finding description ({severity.name})",
        severity=severity,
        category=Category.AGENT_CONFIG,
        file_path="src/test.py",
        line_number=42,
        evidence="some evidence",
        remediation="fix it",
    )


def _mk_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        scan_duration_ms=1.0,
        files_scanned=1,
        rules_evaluated=1,
    )


# -------------------- SlackSink --------------------


def test_slack_sink_posts_findings_above_threshold() -> None:
    """SlackSink should POST to the webhook when at least one finding
    meets the severity floor."""
    sink = SlackSink(
        webhook_url="https://hooks.slack.test/services/X/Y/Z",
        min_severity=Severity.HIGH,
    )
    findings = [
        _mk_finding(Severity.LOW),
        _mk_finding(Severity.HIGH),
        _mk_finding(Severity.CRITICAL),
    ]
    captured: list[dict] = []

    class _MockResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self) -> bytes: return b""

    def _fake_urlopen(req, timeout=10):
        captured.append({
            "url": req.full_url,
            "method": req.get_method(),
            "body": json.loads(req.data.decode("utf-8")),
        })
        return _MockResp()

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        count = sink.send(findings, _mk_result(findings))

    assert count == 2  # HIGH + CRITICAL only; LOW was below floor
    assert len(captured) == 1
    body = captured[0]["body"]
    assert "AgentAuditKit found 2 finding(s)" in body["text"]
    assert len(body["attachments"]) == 2
    assert body["attachments"][0]["color"]  # color was assigned
    assert "AAK-TEST-001" in body["attachments"][0]["title"]


def test_slack_sink_skips_when_below_threshold() -> None:
    """SlackSink must not POST when no finding meets the floor."""
    sink = SlackSink(
        webhook_url="https://hooks.slack.test/services/X/Y/Z",
        min_severity=Severity.HIGH,
    )
    findings = [_mk_finding(Severity.LOW), _mk_finding(Severity.MEDIUM)]
    posted: list = []

    def _fake_urlopen(req, timeout=10):
        posted.append(req.full_url)
        raise AssertionError("should not have called Slack")

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        count = sink.send(findings, _mk_result(findings))

    assert count == 0
    assert posted == []


def test_slack_sink_raises_on_http_error() -> None:
    """A 4xx/5xx from Slack must surface as RuntimeError, not silently swallow."""
    import urllib.error
    import io

    sink = SlackSink(
        webhook_url="https://hooks.slack.test/services/X/Y/Z",
        min_severity=Severity.HIGH,
    )
    findings = [_mk_finding(Severity.HIGH)]

    def _fake_urlopen(req, timeout=10):
        raise urllib.error.HTTPError(
            req.full_url, 403, "Forbidden", {}, io.BytesIO(b"invalid_token"),
        )

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        with pytest.raises(RuntimeError, match="Slack webhook returned 403"):
            sink.send(findings, _mk_result(findings))


# -------------------- Stub sinks --------------------


# These two used to assert `NotImplementedError, match="v0.4.0 stub"`. The
# stubs promised v0.4.0 and were still stubs at v0.6.1; both ship as of v0.6.2,
# so the tests now exercise the wire format instead of the promise.


def _mock_urlopen(captured: list, body: bytes = b"{}"):
    class _MockResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self) -> bytes: return body

    def _fake(req, timeout=10):
        captured.append((req.full_url, json.loads(req.data.decode("utf-8")), dict(req.headers)))
        return _MockResp()
    return _fake


def test_pagerduty_sink_posts_one_trigger_event_per_finding() -> None:
    captured: list = []
    sink = PagerDutySink(routing_key="rk", min_severity=Severity.CRITICAL)
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(captured)):
        sent = sink.send([_mk_finding(Severity.CRITICAL)], _mk_result([]))
    assert sent == 1
    url, payload, _ = captured[0]
    assert url == "https://events.pagerduty.com/v2/enqueue"
    assert payload["routing_key"] == "rk"
    assert payload["event_action"] == "trigger"
    assert payload["payload"]["severity"] == "critical"


def test_pagerduty_dedup_key_is_stable_across_runs() -> None:
    """PagerDuty dedups on this. Without it, every CI run opens a new incident."""
    captured: list = []
    sink = PagerDutySink(routing_key="rk", min_severity=Severity.CRITICAL)
    finding = _mk_finding(Severity.CRITICAL)
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(captured)):
        sink.send([finding], _mk_result([]))
        sink.send([finding], _mk_result([]))
    assert captured[0][1]["dedup_key"] == captured[1][1]["dedup_key"]
    assert captured[0][1]["dedup_key"].startswith("aak:")


def test_pagerduty_sink_requires_a_routing_key() -> None:
    sink = PagerDutySink(routing_key="", min_severity=Severity.CRITICAL)
    with pytest.raises(RuntimeError, match="routing_key"):
        sink.send([_mk_finding(Severity.CRITICAL)], _mk_result([]))


def test_linear_sink_creates_one_issue_per_finding() -> None:
    captured: list = []
    sink = LinearTicketSink(api_key="lin_x", team_id="ENG", min_severity=Severity.HIGH)
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(captured)):
        sent = sink.send([_mk_finding(Severity.HIGH)], _mk_result([]))
    assert sent == 1
    url, payload, headers = captured[0]
    assert url == "https://api.linear.app/graphql"
    assert "IssueCreate" in payload["query"]
    assert payload["variables"]["input"]["teamId"] == "ENG"
    assert headers.get("Authorization") == "lin_x"


def test_linear_sink_raises_on_graphql_errors_despite_http_200() -> None:
    """GraphQL answers 200 with an `errors` array.

    A bad team id or a revoked key looks like success to anything that only
    checks the status code, which is the failure mode worth a test.
    """
    captured: list = []
    body = b'{"errors":[{"message":"Team not found"}]}'
    sink = LinearTicketSink(api_key="k", team_id="NOPE", min_severity=Severity.HIGH)
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(captured, body)):
        with pytest.raises(RuntimeError, match="Team not found"):
            sink.send([_mk_finding(Severity.HIGH)], _mk_result([]))


def test_linear_sink_requires_api_key_and_team_id() -> None:
    with pytest.raises(RuntimeError, match="api_key and team_id"):
        LinearTicketSink(api_key="", team_id="", min_severity=Severity.HIGH).send(
            [_mk_finding(Severity.HIGH)], _mk_result([])
        )


# -------------------- load_notify_config --------------------


def test_load_notify_config_slack(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    cfg_path = tmp_path / ".aak-notify.yaml"
    cfg_path.write_text(
        "sinks:\n"
        "  - kind: slack\n"
        "    webhook_url_env: SLACK_WEBHOOK_URL\n"
        "    min_severity: medium\n",
        encoding="utf-8",
    )
    cfg = load_notify_config(cfg_path)
    assert len(cfg.sinks) == 1
    sink = cfg.sinks[0]
    assert isinstance(sink, SlackSink)
    assert sink.webhook_url == "https://hooks.slack.test/x"
    assert sink.min_severity == Severity.MEDIUM


def test_load_notify_config_missing_webhook_env_raises(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    cfg_path = tmp_path / ".aak-notify.yaml"
    cfg_path.write_text(
        "sinks:\n  - kind: slack\n    webhook_url_env: SLACK_WEBHOOK_URL\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="env var .* is unset"):
        load_notify_config(cfg_path)


def test_load_notify_config_unknown_kind_raises(tmp_path: Path) -> None:
    cfg_path = tmp_path / ".aak-notify.yaml"
    cfg_path.write_text(
        "sinks:\n  - kind: rocketchat\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown sink kind 'rocketchat'"):
        load_notify_config(cfg_path)


def test_load_notify_config_missing_file_returns_empty(tmp_path: Path) -> None:
    cfg = load_notify_config(tmp_path / "nonexistent.yaml")
    assert cfg.sinks == []


# -------------------- run_notify dispatch --------------------


def test_run_notify_returns_per_sink_counts() -> None:
    findings = [_mk_finding(Severity.HIGH), _mk_finding(Severity.CRITICAL)]
    result = _mk_result(findings)

    captured: list = []

    class _MockResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self) -> bytes: return b""

    def _fake_urlopen(req, timeout=10):
        captured.append(json.loads(req.data.decode("utf-8")))
        return _MockResp()

    cfg = NotifyConfig(sinks=[
        SlackSink(webhook_url="https://hooks.slack.test/x", min_severity=Severity.HIGH),
        PagerDutySink(routing_key="abc", min_severity=Severity.CRITICAL),
    ])
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        sent = run_notify(result, cfg)

    assert sent["slack"] == 2
    # Was -1 (NotImplementedError). PagerDuty now posts, and only the one
    # CRITICAL finding clears its min_severity.
    assert sent["pagerduty"] == 1
    assert len(captured) == 2
