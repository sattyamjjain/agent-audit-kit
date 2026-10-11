import os


def session_exists(authorization: str) -> bool:
    if not authorization.startswith("Bearer "):
        return False
    token = authorization[len("Bearer "):]
    path = os.path.join("sessions", token + ".session")
    return os.path.exists(path)
