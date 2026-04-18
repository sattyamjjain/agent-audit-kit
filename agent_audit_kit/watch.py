"""Continuous drift-detection daemon.

Re-runs `agent-audit-kit verify` on an interval and emits a webhook
(Slack / Discord / generic) when pinned tool surface changes. Closes B6
from the pending-items audit and ROADMAP §2.3(4).

Typical usage:
    # every 5 minutes, POST to $WEBHOOK when pin drift is detected
    AAK_WEBHOOK_URL=$SLACK_WEBHOOK agent-audit-kit watch .

Stops on SIGINT (Ctrl-C). Never raises to the caller; errors are
logged to stderr and the loop continues.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from agent_audit_kit.pinning import verify_pins


@dataclass
class WatchResult:
    iterations: int
    drift_events: int


def _post_webhook(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "agent-audit-kit watch",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10).read()
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"watch: webhook POST failed ({type(exc).__name__}): {exc}\n")


def _shape_for_slack(project: Path, findings: list) -> dict:
    ids = ", ".join(sorted({f.rule_id for f in findings}))
    plural = "s" if len(findings) != 1 else ""
    return {
        "text": (
            f":warning: *Tool-surface drift detected* in `{project}`\n"
            f"{len(findings)} finding{plural}: {ids}\n"
            f"Run `agent-audit-kit verify {project}` to see details."
        ),
    }


def run_watch(
    project_root: Path,
    interval_seconds: int = 300,
    webhook_url: str | None = None,
    max_iterations: int | None = None,
    on_drift: "callable | None" = None,  # type: ignore[valid-type]
) -> WatchResult:
    """Main watch loop.

    Args:
        project_root: project with a .agent-audit-kit/tool-pins.json.
        interval_seconds: seconds between checks. Default 5m.
        webhook_url: HTTP endpoint to POST a Slack-shaped JSON payload.
            Falls back to $AAK_WEBHOOK_URL env. If neither is set, drift
            events are only printed.
        max_iterations: stop after this many checks (for tests). None
            means "until SIGINT".
        on_drift: optional test hook; called with (iteration, findings)
            on each drift detection.
    """
    webhook = webhook_url or os.environ.get("AAK_WEBHOOK_URL")
    iterations = 0
    drift_events = 0
    stop = {"flag": False}

    def _handle_stop(_signum, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    while not stop["flag"]:
        if max_iterations is not None and iterations >= max_iterations:
            break
        iterations += 1
        ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        try:
            findings = verify_pins(project_root)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"watch: verify_pins raised {type(exc).__name__}: {exc}\n")
            findings = []

        if findings:
            drift_events += 1
            sys.stdout.write(
                f"[{ts}] drift: {len(findings)} finding(s) "
                f"({', '.join(sorted({f.rule_id for f in findings}))})\n"
            )
            sys.stdout.flush()
            if webhook:
                _post_webhook(webhook, _shape_for_slack(project_root, findings))
            if on_drift:
                on_drift(iterations, findings)
        else:
            sys.stdout.write(f"[{ts}] clean\n")
            sys.stdout.flush()

        if max_iterations is not None and iterations >= max_iterations:
            break
        if stop["flag"]:
            break
        # sleep with wakeups every 0.5s so SIGINT is responsive
        end = time.monotonic() + interval_seconds
        while not stop["flag"] and time.monotonic() < end:
            time.sleep(min(0.5, max(0.0, end - time.monotonic())))

    return WatchResult(iterations=iterations, drift_events=drift_events)
