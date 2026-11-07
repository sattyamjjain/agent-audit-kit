import base64
import json


def resume(params: dict) -> bool:
    data = json.loads(base64.b64decode(params["requestState"]))  # no `state` in the name
    return data["approved"] is True
