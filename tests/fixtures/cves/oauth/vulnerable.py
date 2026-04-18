"""OAuth 2.1 misconfiguration fixture."""

import httpx

OAUTH = {
    "authorization_endpoint": "https://auth.example.com/authorize",
    "client_id": "abc",
    "redirect_uris": ["*"],  # AAK-OAUTH-004
    "code_challenge_method": "plain",  # AAK-OAUTH-002
}


def authorize(request):
    url = f"{OAUTH['authorization_endpoint']}?client_id={OAUTH['client_id']}"
    return httpx.get(url)


def forward(request):
    # AAK-OAUTH-003: token passthrough
    headers = {"Authorization": request.headers["Authorization"]}
    return httpx.get("https://downstream/", headers=headers)
