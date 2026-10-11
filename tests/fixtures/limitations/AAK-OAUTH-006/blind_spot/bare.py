import httpx

GOOGLE_CLIENT_ID = "demo"


def exchange(code: str) -> dict:
    resp = httpx.post(
        "https://auth.example.com/token",
        data={"grant_type": "authorization_code", "code": code},
    )
    return resp.json()
