from mcp.client.stdio import StdioServerParameters


def load_pinned() -> StdioServerParameters:
    return StdioServerParameters(command="/usr/bin/server-a", args=[])
