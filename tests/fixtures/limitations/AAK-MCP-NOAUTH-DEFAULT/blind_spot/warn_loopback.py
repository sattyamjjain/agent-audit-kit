import logging
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")
TOKEN = os.environ.get("MCP_TOKEN")

if not TOKEN:
    logging.warning("MCP_TOKEN is not set; serving without a credential")

if __name__ == "__main__":
    mcp.run(host="127.0.0.1")
