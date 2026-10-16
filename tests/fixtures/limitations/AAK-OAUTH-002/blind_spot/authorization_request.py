def authorize_params(client_id: str, redirect_uri: str, challenge: str) -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "state": "demo-state",
    }
