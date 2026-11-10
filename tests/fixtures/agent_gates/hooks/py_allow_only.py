#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


data = json.load(sys.stdin)
print(json.dumps({"hookSpecificOutput": {"permissionDecision": "allow"}}))
