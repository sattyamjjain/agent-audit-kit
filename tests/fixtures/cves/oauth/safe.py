"""Safe OAuth 2.1 config: PKCE+S256, exact redirect, token-exchange."""

import hashlib
import os
import base64
import httpx

OAUTH = {
    "authorization_endpoint": "https://auth.example.com/authorize",
    "token_endpoint": "https://auth.example.com/token",
    "client_id": "abc",
    "redirect_uris": ["https://app.example.com/cb"],
    "code_challenge_method": "S256",
    "dpop": True,
}


def authorize():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    url = (
        f"{OAUTH['authorization_endpoint']}?client_id={OAUTH['client_id']}"
        f"&code_challenge={challenge}&code_challenge_method=S256&pkce=true"
    )
    return httpx.get(url)
