"""Notification sinks for AAK findings (Slack / PagerDuty / Linear).

Closes #66. All three sinks are implemented: Slack via incoming webhook,
PagerDuty via Events API v2, Linear via the GraphQL IssueCreate mutation.
PagerDuty and Linear were stubs from v0.3.13 until v0.6.2.
"""
from __future__ import annotations

from agent_audit_kit.integrations.notify import (
    LinearTicketSink,
    NotifyConfig,
    NotifySink,
    PagerDutySink,
    SlackSink,
    load_notify_config,
    run_notify,
)

__all__ = [
    "LinearTicketSink",
    "NotifyConfig",
    "NotifySink",
    "PagerDutySink",
    "SlackSink",
    "load_notify_config",
    "run_notify",
]
