from app import work
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData


def run() -> None:
    try:
        work()
    except ValueError as exc:
        raise McpError(ErrorData(code=-32000, message=str(exc)))
