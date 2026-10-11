import httpx


def exchange(code: str, id_token_claims: dict) -> dict:
    """Redeem an OAuth authorization code."""
    resp = httpx.post(
        "https://auth.example.com/token",
        data={"grant_type": "authorization_code", "code": code, "client_id": "demo"},
    )
    if id_token_claims["iss"] != "https://auth.example.com":
        raise ValueError("unexpected issuer in the ID token")
    return resp.json()
