"""Vulnerable: TikTok auto-reply ingests comments and replies via tool
loop without a human-in-loop gate. BlackHat Asia 2026 hijack class."""
from __future__ import annotations

import tiktok_api  # type: ignore[import-not-found]


def auto_reply_loop(media_id: str) -> None:
    comments = tiktok_api.comments.fetch(media_id)
    for c in comments:
        reply_text = generate_reply(c["text"])
        tiktok_api.reply(c["id"], reply_text)


def generate_reply(text: str) -> str:
    return f"thanks: {text[:50]}"
