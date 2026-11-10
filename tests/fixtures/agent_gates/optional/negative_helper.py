"""The shape of the upstream fix: a helper refuses every input left unknown.

`if x is False` stays, because False is still the explicit no, and None never gets there.
"""

from __future__ import annotations

from typing import Optional


def _unasserted(has_pin: bool, key_matches_pin: Optional[bool]) -> Optional[str]:
    if has_pin and key_matches_pin is None:
        return "pin_not_checked"
    return None


def classify(has_pin: bool, key_matches_pin: Optional[bool] = None) -> str:
    refused = _unasserted(has_pin, key_matches_pin)
    if refused:
        return refused
    if key_matches_pin is False:
        return "untrusted_key"
    return "positive_evidence"
