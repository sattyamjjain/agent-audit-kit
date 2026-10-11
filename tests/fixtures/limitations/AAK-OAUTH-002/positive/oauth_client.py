def params(challenge: str) -> dict:
    return {
        "client_id": "demo-client",
        "code_challenge": challenge,
        "code_challenge_method": "plain",
    }
