import anthropic

client = anthropic.Anthropic()


def review(event: dict) -> str:
    title = event["pull_request"]["title"]
    prompt = f"Review this change: {title}"
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return reply.content[0].text
