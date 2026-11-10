import base64
import hashlib
import hmac
import json
import time


def resume(params: dict, key: bytes, caller: str, method: str) -> bool:
    raw, mac = params["requestState"].split(".")
    if not hmac.compare_digest(mac, hmac.new(key, raw.encode(), "sha256").hexdigest()):
        return False
    state = json.loads(base64.b64decode(raw))
    digest = hashlib.sha256(method.encode()).hexdigest()
    if state["principal"] != caller or state["expires"] < time.time() or state["digest"] != digest:
        return False
    return state["approved"] is True
