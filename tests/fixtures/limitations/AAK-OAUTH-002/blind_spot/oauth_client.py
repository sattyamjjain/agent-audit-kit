METHOD = "plain"


def params(challenge: str) -> dict:
    return {"client_id": "demo-client", "code_challenge": challenge}


def params_with_method(challenge: str) -> dict:
    return {
        "client_id": "demo-client",
        "code_challenge": challenge,
        "code_challenge_method": METHOD,
    }
