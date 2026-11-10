from __future__ import annotations

from typing import Optional


def under_a_tests_directory(key_matches_pin: Optional[bool] = None) -> str:
    if key_matches_pin is False:
        return "untrusted_key"
    return "positive_evidence"
