"""Leaving the argument out says nothing was revoked."""

from __future__ import annotations


def admit(request: dict, revoked: bool = False) -> dict:
    if revoked:
        raise PermissionError("revoked")
    return request
