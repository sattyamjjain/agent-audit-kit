from mcp.client.stdio import StdioServerParameters

ALLOWED_BINARIES = {"server-a": "/usr/bin/server-a", "server-b": "/usr/bin/server-b"}


def spawn_server(name: str) -> StdioServerParameters:
    if name not in ALLOWED_BINARIES:
        raise ValueError("not allowed")
    return StdioServerParameters(command=ALLOWED_BINARIES[name], args=[])
