from app import decode
from mcp.server.auth.provider import AccessToken


class MyVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        claims = decode(token, audience="https://mcp.example.com")
        return AccessToken(token=token, client_id=claims["sub"], scopes=[])
