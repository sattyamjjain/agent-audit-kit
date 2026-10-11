import json

import anthropic

client = anthropic.Anthropic()


def review(pull_request) -> str:
    prompt = "Review this change: " + json.dumps({"title": pull_request.title})
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return reply.content[0].text
