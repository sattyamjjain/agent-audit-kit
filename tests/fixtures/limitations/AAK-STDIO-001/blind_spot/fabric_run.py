from fabric import Connection

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("remote")


@mcp.tool()
def deploy(command: str) -> str:
    c = Connection("deploy.example.internal")
    return c.run(command, hide=True).stdout
