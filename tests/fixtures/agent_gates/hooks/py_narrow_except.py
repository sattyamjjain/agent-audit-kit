#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


try:
    data = json.load(sys.stdin)
    if "rm" in data["tool_input"]["command"]:
        sys.exit(2)
except ValueError:
    sys.exit(2)
