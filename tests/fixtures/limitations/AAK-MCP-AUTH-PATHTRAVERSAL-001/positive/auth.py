import os


def session_exists(token: str) -> bool:
    path = os.path.join("sessions", token + ".session")
    return os.path.exists(path)
