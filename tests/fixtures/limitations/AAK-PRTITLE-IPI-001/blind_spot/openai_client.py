from openai import OpenAI

client = OpenAI()


def review(pull_request) -> str:
    prompt = f"Review this change: {pull_request.title}"
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return reply.choices[0].message.content
