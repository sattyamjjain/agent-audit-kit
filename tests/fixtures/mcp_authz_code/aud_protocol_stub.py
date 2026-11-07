from typing import Protocol


class TokenVerifier(Protocol):
    async def verify_token(self, token: str) -> object:
        """Verify a bearer token."""
