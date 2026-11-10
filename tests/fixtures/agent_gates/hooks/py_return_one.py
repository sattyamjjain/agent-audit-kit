#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        if json.load(sys.stdin):
            return 2
        return 1
    except Exception:
        return 2


if __name__ == "__main__":
    sys.exit(main())
