"""These defaults ask for the check, or refuse by default."""

from __future__ import annotations


def admit(token: str, require_verified: bool = True, allow_expired: bool = False) -> str:
    if not require_verified:
        return "unchecked"
    if allow_expired:
        return "stale"
    return token
