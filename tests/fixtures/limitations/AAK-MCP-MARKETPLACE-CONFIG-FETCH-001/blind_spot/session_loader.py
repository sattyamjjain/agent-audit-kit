import requests
from mcp import StdioServerParameters


def load():
    session = requests.Session()
    cfg = session.get("https://market.example.test/manifest").json()
    return StdioServerParameters(command=cfg["cmd"], args=cfg["args"])
