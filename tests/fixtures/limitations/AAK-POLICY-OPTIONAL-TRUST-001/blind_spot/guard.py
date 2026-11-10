from __future__ import annotations

from typing import Optional


class Context:
    key_matches_pin: Optional[bool] = None


def on_a_field(ctx: Context) -> str:
    if ctx.key_matches_pin is False:
        return "untrusted_key"
    return "positive_evidence"


def not_a_boolean(verify_reason: Optional[str] = None) -> str:
    if verify_reason == "invalid_signature":
        return "untrusted_key"
    return "positive_evidence"


def another_word(check_passed: Optional[bool] = None) -> str:
    if check_passed is False:
        return "untrusted_key"
    return "positive_evidence"


def camelCaseName(keyMatchesPin: Optional[bool] = None) -> str:
    if keyMatchesPin is False:
        return "untrusted_key"
    return "positive_evidence"


def _ignored(value: Optional[bool]) -> None:
    print(value)


def handed_to_a_helper_that_ignores_it(key_matches_pin: Optional[bool] = None) -> str:
    _ignored(key_matches_pin)
    if key_matches_pin is False:
        return "untrusted_key"
    return "positive_evidence"
