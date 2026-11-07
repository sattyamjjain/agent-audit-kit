"""Refuses only on an explicit False, so a caller that checked nothing passes."""

from __future__ import annotations

from typing import Optional


def classify(document: dict, key_matches_pin: Optional[bool] = None) -> str:
    if key_matches_pin is False:
        return "untrusted_key"
    return "positive_evidence" if document else "gap"
