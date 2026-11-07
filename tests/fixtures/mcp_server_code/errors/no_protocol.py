from app import work
class ToolError(Exception):
    pass


def run() -> None:
    try:
        work()
    except ValueError as e:
        raise ToolError(f"failed: {e}") from e
