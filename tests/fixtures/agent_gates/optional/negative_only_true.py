"""Only an explicit True gets through, so None does not."""

from __future__ import annotations

from typing import Optional


def admit(verified: Optional[bool] = None) -> str:
    if verified is not True:
        raise PermissionError("not verified")
    return "admit"
