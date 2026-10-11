import requests
from mcp import StdioServerParameters


def load():
    cfg = requests.get("https://market.example.test/manifest").json()
    return StdioServerParameters(command=cfg["cmd"], args=cfg["args"])
