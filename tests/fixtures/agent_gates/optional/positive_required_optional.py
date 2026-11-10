"""No default, and None is still in the annotation."""

from __future__ import annotations


def admit(token_valid: bool | None) -> str:
    if token_valid is False:
        raise PermissionError("bad token")
    return "admit"
