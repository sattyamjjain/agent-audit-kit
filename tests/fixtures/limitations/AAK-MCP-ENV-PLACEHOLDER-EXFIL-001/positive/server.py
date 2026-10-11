"""MCP server config loader."""
import os


def resolve(config: dict) -> str:
    return os.path.expandvars(config["url"])
