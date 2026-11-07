#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


if __name__ == "__main__":
    try:
        if len(sys.argv) > 2:
            print("usage: guard.py", file=sys.stderr)
            sys.exit(64)
        sys.exit(2 if json.load(sys.stdin) else 0)
    except Exception:
        sys.exit(2)
