"""MCP server config loader."""
import os
import re


def resolve(config: dict) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), config["url"])
