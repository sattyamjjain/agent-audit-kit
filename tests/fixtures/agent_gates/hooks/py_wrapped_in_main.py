#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


def main() -> int:
    """Everything is inside the try."""
    try:
        data = json.load(sys.stdin)
        return 2 if "rm" in data["tool_input"]["command"] else 0
    except BaseException:
        return 2


if __name__ == "__main__":
    sys.exit(main())
