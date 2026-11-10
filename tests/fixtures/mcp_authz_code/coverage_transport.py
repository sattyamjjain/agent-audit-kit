from app import authorize, run


def dispatch(transport: str, request: dict) -> dict:
    if transport == "sse":
        authorize(request)
    return run(request)
