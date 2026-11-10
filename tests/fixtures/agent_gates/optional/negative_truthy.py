"""`if not x` takes None down the refusing path."""

from __future__ import annotations

from typing import Optional


def admit(verified: Optional[bool] = None) -> str:
    if not verified:
        raise PermissionError("not verified")
    return "admit"
