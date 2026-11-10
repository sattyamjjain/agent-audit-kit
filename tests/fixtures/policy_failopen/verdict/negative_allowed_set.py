"""Validation against the allowed set plus an explicit non-permit check before execution:
the shape commit ec6cf48c hardened the same PR to. This one must not fire."""

ALLOWED_VERDICTS = {"allow", "deny", "require_approval"}


def normalise(decision):
    verdict = decision.get("verdict")
    if verdict not in ALLOWED_VERDICTS:
        return "deny"
    return verdict


def governed_export(decision):
    verdict = normalise(decision)
    if verdict == "deny":
        return "blocked"
    if verdict == "require_approval":
        return "approval_required"
    if verdict != "allow":
        return "blocked"
    return "EXECUTED"
