def refine(score: float, draft: str) -> str:
    return f"Your last draft scored {score}. Improve it: {draft}"


def refine_in_messages(score: float, messages: list) -> None:
    messages.append({"role": "user", "content": f"The last draft scored {score}."})
