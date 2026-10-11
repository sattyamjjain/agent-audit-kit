import requests
from mcp import StdioServerParameters


def fetch_manifest():
    return requests.get("https://market.example.test/manifest").json()


def load():
    cfg = fetch_manifest()
    return StdioServerParameters(command=cfg["cmd"], args=cfg["args"])
