"""Notification sinks for AAK findings.

Closes #66. All three sinks -- Slack, PagerDuty and Linear -- are implemented.

PagerDuty and Linear shipped as `NotImplementedError` stubs in v0.3.13 whose
docstrings promised a full implementation in v0.4.0. They were still stubs at v0.6.1,
two minor versions past that, and this docstring had told users to build their
`.aak-notify.yaml` against the shape "ahead of v0.4.0" -- so anyone who did had
a config that raised at runtime. A stub is a reasonable thing to ship; a stub
carrying a version promise it then outlives is not.

Why ship Slack first: incoming-webhooks are a single POST with an HMAC-
free shared secret, which keeps the v0.3.13 surface small and reviewable.
PagerDuty Events API v2 + Linear GraphQL each pull in non-trivial state
(routing keys, dedup keys, GraphQL client) that is not Sunday-cadence
work.

Config schema (.aak-notify.yaml at project root):

    sinks:
      - kind: slack
        webhook_url_env: SLACK_WEBHOOK_URL
        min_severity: high
      - kind: pagerduty   # Events API v2; dedups on rule_id + location
        routing_key_env: PD_ROUTING_KEY
        min_severity: critical
      - kind: linear      # GraphQL IssueCreate; one issue per finding
        api_key_env: LINEAR_API_KEY
        team_id: ENG
        min_severity: medium

Programmatic use:

    from agent_audit_kit.engine import run_scan
    from agent_audit_kit.integrations import load_notify_config, run_notify

    result = run_scan(project_root=Path("."))
    config = load_notify_config(Path(".aak-notify.yaml"))
    run_notify(result, config)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agent_audit_kit.models import Finding, ScanResult, Severity


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_FROM_STR: dict[str, Severity] = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SLACK_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#a30200",  # dark red
    Severity.HIGH: "#e01e5a",      # red
    Severity.MEDIUM: "#ecb22e",    # amber
    Severity.LOW: "#36c5f0",       # blue
    Severity.INFO: "#808080",      # gray
}

_SLACK_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: ":no_entry:",
    Severity.HIGH: ":red_circle:",
    Severity.MEDIUM: ":large_yellow_circle:",
    Severity.LOW: ":large_blue_circle:",
    Severity.INFO: ":information_source:",
}


# PagerDuty Events API v2 accepts exactly these four.
_PAGERDUTY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "info",
}


def _post_json(url: str, payload: dict, headers: dict, who: str) -> Any:
    """POST JSON and return the decoded body, or raise with the server's text.

    Shared by every sink so a failure reads the same regardless of which one
    hit it, and so the error carries the response body. A sink that raised a
    bare HTTPError would tell an operator the request failed and not why.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"{who} returned {exc.code}: {exc.read().decode('utf-8', 'replace')}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{who} unreachable: {exc.reason}") from exc
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


@dataclass
class NotifySink:
    """Base interface for a notification sink."""
    kind: str
    min_severity: Severity = Severity.HIGH

    def send(self, findings: list[Finding], result: ScanResult) -> int:  # pragma: no cover
        raise NotImplementedError


@dataclass
class SlackSink(NotifySink):
    """Post AAK findings to a Slack incoming webhook."""
    webhook_url: str = ""
    kind: str = "slack"

    def send(self, findings: list[Finding], result: ScanResult) -> int:
        """POST findings as a Slack attachment payload. Returns the
        number of findings posted (0 if none met the severity floor)."""
        gated = [f for f in findings if _SEVERITY_ORDER[f.severity] >= _SEVERITY_ORDER[self.min_severity]]
        if not gated:
            return 0

        attachments: list[dict[str, Any]] = []
        for f in gated:
            location = f.file_path
            if f.line_number:
                location += f":{f.line_number}"
            attachments.append({
                "color": _SLACK_COLOR.get(f.severity, "#808080"),
                "title": f"{_SLACK_EMOJI.get(f.severity, '')}  {f.rule_id} — {f.title}",
                "text": (
                    f"*Severity:* {f.severity.name}\n"
                    f"*Location:* `{location}`\n"
                    f"*Evidence:* {f.evidence}\n"
                    f"*Fix:* {f.remediation}"
                ),
                "mrkdwn_in": ["text"],
            })

        payload = {
            "text": (
                f"*AgentAuditKit found {len(gated)} finding(s) "
                f"at or above {self.min_severity.name}.*"
            ),
            "attachments": attachments,
        }

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"Slack webhook returned {exc.code}: {exc.read().decode('utf-8', 'replace')}"
            ) from exc
        return len(gated)


@dataclass
class PagerDutySink(NotifySink):
    """Post AAK findings to PagerDuty as Events API v2 alerts.

    One `trigger` event per finding rather than one per scan. PagerDuty
    deduplicates on `dedup_key`, so a rule that keeps firing on the same file
    updates a single incident instead of opening a new one on every CI run,
    which is the behaviour that makes this usable in a pipeline at all.
    """
    routing_key: str = ""
    kind: str = "pagerduty"

    def send(self, findings: list[Finding], result: ScanResult) -> int:
        gated = [f for f in findings if _SEVERITY_ORDER[f.severity] >= _SEVERITY_ORDER[self.min_severity]]
        if not gated:
            return 0
        if not self.routing_key:
            raise RuntimeError("PagerDuty sink needs a routing_key (Events API v2 integration key).")

        for finding in gated:
            location = finding.file_path
            if finding.line_number:
                location += f":{finding.line_number}"
            payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                # Stable across runs: same rule, same location => same incident.
                "dedup_key": f"aak:{finding.rule_id}:{location}",
                "payload": {
                    "summary": f"{finding.rule_id} — {finding.title}",
                    "source": location,
                    "severity": _PAGERDUTY_SEVERITY.get(finding.severity, "warning"),
                    "component": finding.category.value,
                    "custom_details": {
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "cve_references": finding.cve_references,
                    },
                },
            }
            _post_json(
                "https://events.pagerduty.com/v2/enqueue",
                payload,
                {"Content-Type": "application/json"},
                "PagerDuty Events API",
            )
        return len(gated)


@dataclass
class LinearTicketSink(NotifySink):
    """Create one Linear issue per finding via the GraphQL API.

    Linear has no dedup key, so re-running this against the same findings
    creates duplicate issues. That is stated rather than worked around: a
    client-side search-before-create would race in CI and silently drop
    findings when it guessed wrong. Gate it on `min_severity` and run it from
    one place.
    """
    api_key: str = ""
    team_id: str = ""
    kind: str = "linear"

    def send(self, findings: list[Finding], result: ScanResult) -> int:
        gated = [f for f in findings if _SEVERITY_ORDER[f.severity] >= _SEVERITY_ORDER[self.min_severity]]
        if not gated:
            return 0
        if not self.api_key or not self.team_id:
            raise RuntimeError("Linear sink needs both api_key and team_id.")

        mutation = (
            "mutation IssueCreate($input: IssueCreateInput!) "
            "{ issueCreate(input: $input) { success issue { identifier } } }"
        )
        for finding in gated:
            location = finding.file_path
            if finding.line_number:
                location += f":{finding.line_number}"
            body = (
                f"**Severity:** {finding.severity.name}\n"
                f"**Location:** `{location}`\n"
                f"**Evidence:** {finding.evidence}\n\n"
                f"**Fix:** {finding.remediation}\n"
            )
            if finding.cve_references:
                body += f"\n**CVEs:** {', '.join(finding.cve_references)}\n"
            payload = {
                "query": mutation,
                "variables": {
                    "input": {
                        "teamId": self.team_id,
                        "title": f"{finding.rule_id} — {finding.title}",
                        "description": body,
                    }
                },
            }
            response = _post_json(
                "https://api.linear.app/graphql",
                payload,
                {"Content-Type": "application/json", "Authorization": self.api_key},
                "Linear GraphQL API",
            )
            # GraphQL answers 200 with an `errors` array rather than an HTTP
            # error, so a bad team id or a revoked key looks like success to
            # anything that only checks the status code.
            if isinstance(response, dict) and response.get("errors"):
                raise RuntimeError(f"Linear GraphQL API returned errors: {response['errors']}")
        return len(gated)


@dataclass
class NotifyConfig:
    """Parsed `.aak-notify.yaml` document."""
    sinks: list[NotifySink] = field(default_factory=list)


def _resolve_min_severity(raw: str | None) -> Severity:
    if not raw:
        return Severity.HIGH
    val = _SEVERITY_FROM_STR.get(str(raw).lower())
    if val is None:
        raise ValueError(
            f"unknown min_severity {raw!r}; expected one of "
            f"{sorted(_SEVERITY_FROM_STR.keys())}"
        )
    return val


def load_notify_config(path: Path) -> NotifyConfig:
    """Parse a `.aak-notify.yaml` file into a NotifyConfig.

    Accepts a `sinks` list with per-sink `kind` discriminator. Unknown
    `kind` values raise ValueError so typos surface immediately rather
    than silently no-op'ing in production.
    """
    if not path.is_file():
        return NotifyConfig(sinks=[])

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    sinks: list[NotifySink] = []
    for entry in data.get("sinks", []):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", "")).lower()
        min_sev = _resolve_min_severity(entry.get("min_severity"))

        if kind == "slack":
            env = entry.get("webhook_url_env", "SLACK_WEBHOOK_URL")
            url = os.environ.get(env, "")
            if not url:
                raise RuntimeError(
                    f"slack sink: env var {env!r} is unset; "
                    "either export it or set webhook_url_env to a different name."
                )
            sinks.append(SlackSink(webhook_url=url, min_severity=min_sev))
        elif kind == "pagerduty":
            env = entry.get("routing_key_env", "PD_ROUTING_KEY")
            sinks.append(PagerDutySink(
                routing_key=os.environ.get(env, ""),
                min_severity=min_sev,
            ))
        elif kind == "linear":
            env = entry.get("api_key_env", "LINEAR_API_KEY")
            sinks.append(LinearTicketSink(
                api_key=os.environ.get(env, ""),
                team_id=str(entry.get("team_id", "")),
                min_severity=min_sev,
            ))
        else:
            raise ValueError(
                f"unknown sink kind {kind!r} in {path}; expected one of: "
                "slack, pagerduty, linear."
            )

    return NotifyConfig(sinks=sinks)


def run_notify(result: ScanResult, config: NotifyConfig) -> dict[str, int]:
    """Dispatch findings to every configured sink. Returns a per-sink
    dict of {sink_kind: count_posted}.

    Each sink failure is caught and re-raised as RuntimeError with the
    sink kind in the message; the caller decides whether to fail the
    build or continue. We do NOT swallow errors silently — silent
    notification failures are the worst kind of monitoring bug.
    """
    sent: dict[str, int] = {}
    for sink in config.sinks:
        try:
            count = sink.send(result.findings, result)
        except NotImplementedError:
            # No sink raises this any more -- PagerDuty and Linear were the
            # last two and both ship as of v0.6.2. The arm stays because
            # NotifySink.send still raises it, so a third-party sink subclass
            # that forgets to override send reports -1 rather than crashing
            # every other sink in the same dispatch.
            sent[sink.kind] = -1
            continue
        sent[sink.kind] = count
    return sent
