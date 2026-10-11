import httpx


def exchange(code: str) -> dict:
    """Redeem an OAuth authorization code."""
    resp = httpx.post(
        "https://auth.example.com/token",
        data={"grant_type": "authorization_code", "code": code, "client_id": "demo"},
    )
    return resp.json()
