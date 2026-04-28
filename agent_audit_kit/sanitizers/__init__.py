"""Runtime sanitisers paired with SAST rules.

Each module exposes a `sanitize_*` helper rule consumers can import to
silence the corresponding SAST rule (the rule's pattern looks for a
call into this module).
"""
