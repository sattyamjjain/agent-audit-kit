import litellm


async def quote(item: str, model: str) -> str:
    reply = await litellm.acompletion(
        model=model,
        messages=[{"role": "user", "content": f"Price this item: {item}"}],
    )
    return reply.choices[0].message.content
