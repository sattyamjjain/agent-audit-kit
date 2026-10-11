import httpx

GOOGLE_CLIENT_ID = "demo"


def call_api() -> httpx.Response:
    return httpx.get(
        "https://api.example.com/v1/items",
        headers={"Authorization": "Bearer example-token-value"},
    )
