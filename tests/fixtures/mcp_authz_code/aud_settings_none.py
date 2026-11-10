from app import MyVerifier, MCPServer
from mcp.server.auth.settings import AuthSettings

server = MCPServer(
    "x",
    token_verifier=MyVerifier(),
    auth=AuthSettings(issuer_url="https://issuer.example", resource_server_url=None),
)
