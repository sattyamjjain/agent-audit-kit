"""Safe shape: refusal is discretized + categorized before re-use."""
from __future__ import annotations

from enum import Enum


class RefusalKind(Enum):
    POLICY = 1
    SAFETY = 2
    UNKNOWN = 3


def handle_refusal(refusal_text: str) -> RefusalKind:
    # Categorize — does NOT return the verbatim refusal text.
    if "policy" in refusal_text.lower():
        return RefusalKind.POLICY
    if "safety" in refusal_text.lower():
        return RefusalKind.SAFETY
    return RefusalKind.UNKNOWN
