import httpx


def login_url(client_id: str, redirect: str) -> str:
    meta = httpx.get("https://auth.example.com/.well-known/oauth-authorization-server").json()
    base = meta["authorization_endpoint"]
    return f"{base}?response_type=code&client_id={client_id}&redirect_uri={redirect}"
