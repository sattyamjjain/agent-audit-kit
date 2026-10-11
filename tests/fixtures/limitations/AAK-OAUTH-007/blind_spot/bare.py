import httpx

GOOGLE_CLIENT_ID = "demo"


def fetch_token() -> dict:
    resp = httpx.post(
        "https://auth.example.com/token",
        data={"grant_type": "client_credentials"},
    )
    return resp.json()
