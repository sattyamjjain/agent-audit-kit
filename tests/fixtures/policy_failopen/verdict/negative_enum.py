"""An enum parse that maps unknown values to deny. This one must not fire."""

from enum import Enum


class Verdict(Enum):
    ALLOW = "allow"
    DENY = "deny"


def parse_verdict(raw):
    try:
        return Verdict(raw)
    except ValueError:
        return Verdict.DENY


def governed_export(decision):
    if parse_verdict(decision["verdict"]) is Verdict.DENY:
        return "blocked"
    return "EXECUTED"
