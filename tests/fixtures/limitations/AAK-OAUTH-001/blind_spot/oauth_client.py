def login_url(client_id: str, redirect: str) -> str:
    base = "https://auth.example.com/authorize"
    return f"{base}?response_type=code&client_id={client_id}&redirect_uri={redirect}"
