"""A common word with nothing checked beside it, and no refusal on a passing default."""

from __future__ import annotations

from typing import Optional


def resize(valid: Optional[bool] = None, allowed: bool = True, verified: bool = True) -> int:
    if valid is False:
        return 0
    if not allowed:
        return 1
    print(verified)
    return 2
