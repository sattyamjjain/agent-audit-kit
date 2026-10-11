import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
logger = logging.getLogger(__name__)


class Notes:
    def __init__(self) -> None:
        self.logger = logger

    @mcp.tool()
    def add_note(self, text: str) -> str:
        self.logger.info("adding %s", text)
        return text
