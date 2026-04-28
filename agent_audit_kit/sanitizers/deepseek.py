"""Runtime sanitiser for AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001.

`sanitize_tool_description(text)` collapses control characters,
removes routing-poison tokens, and trims length. Calling it in the
same function as the LLM call suppresses the SAST rule.
"""

from __future__ import annotations

import re

# Routing-poison heuristics: tokens that try to manipulate MoE expert
# selection. Speculative — corpus refresh queues for v0.4.0.
_POISON_RE = re.compile(
    r"""
    (?:
        \[\s*ROUTE\s*:\s*[^\]]+\]
      | \{\{?\s*expert\s*:\s*[^}]+\}?\}?
      | <\|\s*route_id\s*\|>
      | __route__\s*=
      | always\s+(?:route|use|prefer)\s+(?:expert|model)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize_tool_description(text: str, *, max_length: int = 1024) -> str:
    """Strip routing-poison tokens + control characters; truncate to
    `max_length` chars.

    Idempotent. Returns the cleaned string.
    """
    if not text:
        return ""
    cleaned = _CONTROL_RE.sub("", text)
    cleaned = _POISON_RE.sub("[REDACTED]", cleaned)
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "...[truncated]"
    return cleaned
