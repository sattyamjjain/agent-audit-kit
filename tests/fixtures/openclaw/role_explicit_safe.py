"""Safe: OpenClawAgent role explicit constant OR allow-listed."""
from __future__ import annotations

from openclaw import OpenClawAgent  # type: ignore[import-not-found]

from agent_audit_kit.checks.openclaw import assert_role_allowlisted


def handler(request):
    user_role = request.json()["role"]
    assert_role_allowlisted(user_role)
    return [
        OpenClawAgent(name="reader", role="reader"),
        OpenClawAgent(name="exec", role=user_role),
    ]
