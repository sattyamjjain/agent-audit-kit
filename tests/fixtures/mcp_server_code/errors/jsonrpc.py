

def run() -> dict:
    try:
        work()
    except ValueError as exc:
        return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32700, "message": repr(exc)}}
    return {}
