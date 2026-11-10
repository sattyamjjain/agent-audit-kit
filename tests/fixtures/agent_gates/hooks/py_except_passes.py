#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        data = json.load(sys.stdin)
        if "rm" in data["tool_input"]["command"]:
            return 2
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
