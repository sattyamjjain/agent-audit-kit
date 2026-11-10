#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


def main() -> None:
    data = json.load(sys.stdin)
    if "rm" in data["tool_input"]["command"]:
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        sys.exit(2)
