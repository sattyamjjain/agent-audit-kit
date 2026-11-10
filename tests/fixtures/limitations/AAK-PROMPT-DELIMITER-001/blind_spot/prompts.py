import openai


def through_format(message: str) -> str:
    _ = openai
    return "<user_input>{}</user_input>".format(message)


def through_plus(message: str) -> str:
    return "<user_input>" + message + "</user_input>"


def a_call_that_escapes_nothing(message: str) -> str:
    return f"<user_input>{str(message)}</user_input>"


def rebound_from_a_call_that_escapes_nothing(message: str) -> str:
    message = message.strip()
    return f"<user_input>{message}</user_input>"


CAPTURED = "x"


def a_module_value() -> str:
    return f"<user_input>{CAPTURED}</user_input>"
