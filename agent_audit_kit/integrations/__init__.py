"""Notification sinks for AAK findings (Slack / PagerDuty / Linear).

Closes #66 (Slack only in v0.3.13; PagerDuty + Linear are stubs that
raise NotImplementedError to make the surface explicit until they
ship in v0.4.0).
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
