import requests
from mcp.server.fastmcp import FastMCP

from tool_base import ToolBase

mcp = FastMCP("fetcher")


class Fetch(ToolBase):
    # The base that makes this a LangChain tool is defined in tool_base.py.
    def _run(self, url: str) -> str:
        return requests.get(url).text
