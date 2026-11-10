import base64
import hmac
import json


def resume(params: dict, key: bytes) -> bool:
    raw, mac = params["requestState"].split(".")
    if not hmac.compare_digest(mac, hmac.new(key, raw.encode(), "sha1").hexdigest()):
        return False
    state = json.loads(base64.b64decode(raw))
    return state["approved"] is True
