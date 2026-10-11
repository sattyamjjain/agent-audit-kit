import mcp_utils
import requests


def summarize(url: str) -> str:
    return mcp_utils.clean(requests.get(url).text)
