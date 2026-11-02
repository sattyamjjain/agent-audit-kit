from fastmcp import FastMCP
from fastmcp.apps.generative import GenerativeUI

mcp = FastMCP("dashboards")
mcp.add_provider(GenerativeUI())

if __name__ == "__main__":
    mcp.run()
