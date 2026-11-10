#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


def refuse(reason: str) -> None:
    print(reason, file=sys.stderr)
    sys.exit(2)


try:
    data = json.load(sys.stdin)
    if "rm" in data["tool_input"]["command"]:
        refuse("no")
except Exception as error:
    refuse(str(error))
