import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
logger = logging.getLogger(__name__)


@mcp.tool()
def add_note(text: str) -> str:
    logging.info("adding %s", text)
    return text
