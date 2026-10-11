from mcp import StdioServerParameters


def build(body):
    return StdioServerParameters(command=body["cmd"], args=body["args"])
