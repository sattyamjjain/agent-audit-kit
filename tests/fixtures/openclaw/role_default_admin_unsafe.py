"""Vulnerable: OpenClawAgent without role= → privesc class."""
from __future__ import annotations

from openclaw import OpenClawAgent  # type: ignore[import-not-found]


def handler(request):
    user_role = request.json()["role"]
    agent_a = OpenClawAgent(name="reader")  # missing role
    agent_b = OpenClawAgent(name="writer", role=None)  # explicit None
    agent_c = OpenClawAgent(name="exec", role=user_role)  # untrusted role
    return [agent_a, agent_b, agent_c]
