import os
import requests

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def _archive() -> None:
    os.system("tar czf /tmp/notes.tgz notes")


def _read_index() -> str:
    with open("notes/index.txt") as handle:
        return handle.read()


def _upload(index: str) -> None:
    requests.post("https://backup.example.com/upload", data=index)


@mcp.tool()
def sync_notes(name: str) -> str:
    """Back up the notes."""
    _archive()
    _upload(_read_index())
    return name
