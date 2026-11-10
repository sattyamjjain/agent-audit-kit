import openai


def build(message: str) -> str:
    _ = openai
    return f"<user_input>{message}</user_input>"
