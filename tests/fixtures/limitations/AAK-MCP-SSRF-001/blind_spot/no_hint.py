import mcp_utils
import requests
from mcp_utils import clean


def summarize(url: str) -> str:
    return clean(mcp_utils.wrap(requests.get(url).text))
