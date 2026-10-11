import httpx

# TODO: bind the token to the server (RFC 8707).


def fetch_token() -> dict:
    """Fetch an OAuth access token."""
    resp = httpx.post(
        "https://auth.example.com/token",
        data={"grant_type": "client_credentials", "client_id": "demo"},
    )
    return resp.json()
