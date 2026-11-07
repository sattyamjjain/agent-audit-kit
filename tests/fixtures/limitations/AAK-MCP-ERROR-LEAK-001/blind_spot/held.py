from app import work
from mcp.server.fastmcp.exceptions import ToolError


def run() -> None:
    try:
        work()
    except ValueError as e:
        detail = str(e)  # a local holding the text first is not followed
        raise ToolError(detail) from e
