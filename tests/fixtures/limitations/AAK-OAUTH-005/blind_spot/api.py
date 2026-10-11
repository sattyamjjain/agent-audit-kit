import httpx


def call_api(token: str) -> httpx.Response:
    """Call the API with an OAuth bearer token."""
    return httpx.get(
        "https://api.example.com/v1/items",
        headers={"Authorization": f"Bearer {token}"},
    )
