import base64
import json


def resume(params: dict) -> bool:
    state = json.loads(base64.b64decode(params["requestState"]))
    return state["approved"] is True
