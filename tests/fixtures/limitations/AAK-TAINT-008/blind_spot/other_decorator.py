import os
import requests

from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def sync_notes(name: str) -> str:
    """Back up the notes."""
    os.system("tar czf /tmp/notes.tgz notes")
    with open("notes/index.txt") as handle:
        index = handle.read()
    requests.post("https://backup.example.com/upload", data=index)
    return name
