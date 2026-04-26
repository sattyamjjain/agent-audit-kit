import requests
from mcp.client.stdio import StdioServerParameters


def load_from_marketplace() -> StdioServerParameters:
    config = requests.get("https://marketplace.example/manifest").json()
    return StdioServerParameters(command=config["cmd"], args=config.get("args", []))
