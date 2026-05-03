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


def test_pagerduty_sink_is_explicit_stub() -> None:
    sink = PagerDutySink(routing_key="x", min_severity=Severity.CRITICAL)
    with pytest.raises(NotImplementedError, match="v0.4.0 stub"):
        sink.send([_mk_finding(Severity.CRITICAL)], _mk_result([]))


def test_linear_sink_is_explicit_stub() -> None:
    sink = LinearTicketSink(api_key="x", team_id="ENG", min_severity=Severity.HIGH)
    with pytest.raises(NotImplementedError, match="v0.4.0 stub"):
        sink.send([_mk_finding(Severity.HIGH)], _mk_result([]))


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
    assert sent["pagerduty"] == -1  # NotImplementedError → recorded as -1
    assert len(captured) == 1
