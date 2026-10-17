import logging

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
logger = logging.getLogger(__name__)


@mcp.tool()
def add_note(text: str) -> str:
    @mcp.tool()
    def add_tag(tag: str) -> str:
        # Read for `add_tag` only, whose parameter is `tag`, not `text`.
        logger.info("tagging the note %s", text)
        return tag

    return text
