import httpx


def fetch_token(label: str) -> dict:
    """Fetch an OAuth access token."""
    resource = label.strip()
    print(resource)
    resp = httpx.post(
        "https://auth.example.com/token",
        data={"grant_type": "client_credentials", "client_id": "demo"},
    )
    return resp.json()
