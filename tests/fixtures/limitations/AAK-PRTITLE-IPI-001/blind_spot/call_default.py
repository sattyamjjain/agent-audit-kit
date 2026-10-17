import json
import os

import anthropic

client = anthropic.Anthropic()


def review() -> str:
    with open(os.environ["GITHUB_EVENT_PATH"]) as fh:
        event = json.load(fh)
    # A `.get()` default that is itself a call: the title is not read as a source.
    title = event.get("pull_request", dict()).get("title", "")
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": f"Review this change: {title}"}],
    )
    return reply.content[0].text
