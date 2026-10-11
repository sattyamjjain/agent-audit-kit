def handle_refusal(refusal: str, messages: list) -> None:
    messages.append({"role": "user", "content": refusal})


def explain_refusal(refusal: str, messages: list) -> None:
    messages.append(f"The last attempt was refused: {refusal}")
