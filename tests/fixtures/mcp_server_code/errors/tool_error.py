from app import work
from mcp.server.fastmcp.exceptions import ToolError


def run() -> None:
    try:
        work()
    except ValueError as e:
        raise ToolError(f"failed: {e}") from e
