import anthropic

client = anthropic.Anthropic()


def review(pull_request) -> str:
    prompt = f"Review this change: {pull_request.body}"
    reply = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return reply.content[0].text
