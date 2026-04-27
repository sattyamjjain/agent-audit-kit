import os
from anthropic import Anthropic


def review_pr() -> str:
    title = os.environ["PR_TITLE"]
    client = Anthropic()
    response = client.messages.create(
        model="claude-3-5-sonnet-latest",
        messages=[{"role": "user", "content": f"Review this PR titled: {title}"}],
    )
    return response.content[0].text
