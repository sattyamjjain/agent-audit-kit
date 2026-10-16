import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
_logger = logging.getLogger(__name__)


@mcp.tool()
def add_note(text: str) -> str:
    _logger.info("adding %s", text)
    return text
