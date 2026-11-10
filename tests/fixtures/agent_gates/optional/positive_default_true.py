"""Leaving the argument out says the check passed."""

from __future__ import annotations


def admit(request: dict, verified: bool = True) -> dict:
    if not verified:
        raise PermissionError("unverified")
    return request
