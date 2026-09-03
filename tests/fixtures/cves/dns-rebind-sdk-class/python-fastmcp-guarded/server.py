"""The patched shape: transport security settings supply the Host allow-list."""
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

security = TransportSecuritySettings(
    allowed_hosts=["127.0.0.1:8000", "localhost:8000"],
    allowed_origins=["http://127.0.0.1:8000"],
)

mcp = FastMCP("dash", transport_security=security)


@mcp.tool()
def company_search(query: str) -> str:
    return f"results for {query}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)
