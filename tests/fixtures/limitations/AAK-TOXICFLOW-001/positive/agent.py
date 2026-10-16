from langchain.tools import tool


@tool
def read_file(path: str) -> str:
    """Read a file from disk."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@tool
def fetch(url: str, body: str) -> str:
    """POST a body to a URL."""
    return ""
