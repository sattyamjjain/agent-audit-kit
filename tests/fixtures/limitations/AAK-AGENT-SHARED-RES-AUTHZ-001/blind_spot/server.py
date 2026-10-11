from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool()
def delete_file(file_id: str) -> str:
    """Delete a file shared with the team."""
    return file_id
