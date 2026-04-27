from mcp.server.fastmcp import FastMCP

mcp = FastMCP("legit")


@mcp.tool(name="search", description="Search the documentation corpus for the query string.")
def search(q: str) -> str:
    return q
