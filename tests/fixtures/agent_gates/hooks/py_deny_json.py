#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


try:
    data = json.load(sys.stdin)
    decision = "deny" if "rm" in data["tool_input"]["command"] else "allow"
except Exception:
    decision = "deny"
print(json.dumps({"hookSpecificOutput": {"permissionDecision": decision}}))
