from app import work
import logging

from mcp.server.fastmcp.exceptions import ToolError

logger = logging.getLogger(__name__)


def run() -> None:
    try:
        work()
    except ValueError:
        logger.exception("work failed")
        raise ToolError("The request could not be processed.")
