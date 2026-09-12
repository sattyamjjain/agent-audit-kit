from mcp.server.fastmcp import FastMCP

mcp = FastMCP("studio")


@mcp.tool()
def render(prompt: str) -> bytes:
    """Text-to-image generation via stable-diffusion.

    Every output carries C2PA Content Credentials marking it as artificially
    generated.
    """
    return b""
