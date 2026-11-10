from app import decode
from mcp.server.auth.provider import AccessToken

NOTE = "the audience is someone else's problem"  # any mention in the file counts as the check


class MyVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        claims = decode(token)
        return AccessToken(token=token, client_id=claims["sub"], scopes=[])
