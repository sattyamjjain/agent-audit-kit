"""Safe: TikTok auto-reply gated by aak.review.human_in_loop()."""
from __future__ import annotations

import tiktok_api  # type: ignore[import-not-found]
import aak.review  # type: ignore[import-not-found]


def auto_reply_loop(media_id: str) -> None:
    comments = tiktok_api.comments.fetch(media_id)
    for c in comments:
        reply_text = generate_reply(c["text"])
        if aak.review.human_in_loop(reply_text, comment=c):
            tiktok_api.reply(c["id"], reply_text)


def generate_reply(text: str) -> str:
    return f"thanks: {text[:50]}"
