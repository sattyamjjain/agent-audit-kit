"""None is answered in the function itself."""

from __future__ import annotations

from typing import Optional


def admit(key_matches_pin: Optional[bool] = None) -> str:
    if key_matches_pin is None:
        return "not_checked"
    if key_matches_pin is False:
        return "untrusted_key"
    return "admit"
