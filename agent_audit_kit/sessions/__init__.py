"""Session-transcript ingest for the session-scoped rules.

`AAK-AGENT-COMPOSE-002` reads an ordered list of tool calls. The rule itself only
knows how to find `*.session.json` files and JSON under `.aak/sessions/` — a
shape a user exports by hand, and one no agent framework actually writes. This
package normalises the transcripts frameworks *do* write into that same shape,
so the rule fires on real data without changing the rule.
"""

from __future__ import annotations

from agent_audit_kit.sessions.adapters import (
    SUPPORTED_FORMATS,
    detect_format,
    load_transcripts,
    normalize,
    normalize_path,
)

__all__ = [
    "SUPPORTED_FORMATS",
    "detect_format",
    "load_transcripts",
    "normalize",
    "normalize_path",
]
