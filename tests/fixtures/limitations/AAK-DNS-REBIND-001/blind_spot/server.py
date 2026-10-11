from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
