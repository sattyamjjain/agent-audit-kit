import anthropic

client = anthropic.Anthropic()


def quote(item: str, params: dict) -> str:
    reply = client.messages.create(
        max_tokens=64,
        messages=[{"role": "user", "content": f"Price this item: {item}"}],
        **params,
    )
    return reply.content[0].text
