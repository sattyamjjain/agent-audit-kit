"""An exact-match deny check, then execute: the shape of microsoft/autogen PR #7960 at
commit 0cd67042, as the Nobulex failopen corpus records it (github.com/arian-gogani/failopen,
case historical/autogen-verdict). Written here, not copied. A regression pattern, not an
unresolved AutoGen vulnerability."""


def governed_export(decision):
    if decision["verdict"] == "deny":
        return "blocked"
    if decision["verdict"] == "require_approval":
        return "approval_required"
    return "EXECUTED"
