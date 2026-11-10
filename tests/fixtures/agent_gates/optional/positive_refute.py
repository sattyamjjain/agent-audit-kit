"""The same bug read from the other side: None is not revoked."""

from __future__ import annotations

from typing import Union


def admit(key_revoked: Union[bool, None] = None) -> str:
    if key_revoked is True:
        raise PermissionError("revoked")
    return "admit"
