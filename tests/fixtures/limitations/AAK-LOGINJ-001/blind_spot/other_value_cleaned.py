import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
logger = logging.getLogger(__name__)


@mcp.tool()
def add_note(title: str, text: str) -> str:
    label = title.replace("\n", " ")
    logger.info("adding %s: %s", label, text)
    return text
