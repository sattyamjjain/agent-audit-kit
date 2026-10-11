import anthropic

client = anthropic.Anthropic()


def get_quote(item: str, model: str) -> str:
    reply = client.messages.create(
        model=model,
        max_tokens=64,
        messages=[{"role": "user", "content": f"Price this item: {item}"}],
    )
    return reply.content[0].text
