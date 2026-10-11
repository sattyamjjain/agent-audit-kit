import httpx


def forward(request) -> httpx.Response:
    """Forward the caller's OAuth token to the downstream API."""
    headers = {"Authorization": request.headers.get("Authorization")}
    return httpx.get("https://api.example.com/v1/items", headers=headers)
