from app import authorize, run


def dispatch(transport: str, request: dict) -> dict:
    if transport != "stdio":
        authorize(request)
    return run(request)
