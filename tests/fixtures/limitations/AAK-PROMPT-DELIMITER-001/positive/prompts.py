import openai


def build(message: str) -> str:
    _ = openai
    return f"Classify this.\n<user_input>{message}</user_input>"
