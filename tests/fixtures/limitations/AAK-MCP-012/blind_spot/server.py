from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


class Settings:
    allowed_ips: list[str] = []
    ip_whitelist = []
