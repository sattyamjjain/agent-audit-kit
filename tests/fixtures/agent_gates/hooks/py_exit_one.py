#!/usr/bin/env python3
"""A PreToolUse gate."""

from __future__ import annotations

import json
import sys


try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if data:
    sys.exit(2)
