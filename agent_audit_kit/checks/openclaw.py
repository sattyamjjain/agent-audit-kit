"""Runtime guard for AAK-OPENCLAW-PRIVESC-001 (provisional).

`assert_role_allowlisted(role, allowlist=...)` rejects anything not on
the allow-list. Calling it in the same function as `OpenClawAgent(...)`
suppresses the SAST rule.
"""
from __future__ import annotations


_DEFAULT_ALLOWLIST: frozenset[str] = frozenset({
    "reader", "writer", "executor", "researcher", "reviewer",
})


class OpenClawRoleError(ValueError):
    """Raised when an OpenClaw role is missing, None, or not allowed."""


def assert_role_allowlisted(
    role: object,
    allowlist: frozenset[str] | set[str] | list[str] | None = None,
) -> str:
    """Validate `role` against an allow-list.

    Args:
        role: Role string proposed for OpenClawAgent(role=...).
        allowlist: Acceptable role names; defaults to a built-in set.

    Returns:
        The role string on success.

    Raises:
        OpenClawRoleError: If role is None, empty, or not in the
            allow-list.
    """
    allowed = (
        frozenset(allowlist) if allowlist is not None else _DEFAULT_ALLOWLIST
    )
    if role is None or role == "":
        raise OpenClawRoleError(
            "OpenClaw role missing — IronPlate 2026-04-07 privesc class."
        )
    if not isinstance(role, str):
        raise OpenClawRoleError(
            f"OpenClaw role must be str, got {type(role).__name__}."
        )
    if role not in allowed:
        raise OpenClawRoleError(
            f"OpenClaw role {role!r} not in allow-list {sorted(allowed)}."
        )
    return role


__all__ = ["OpenClawRoleError", "assert_role_allowlisted"]
