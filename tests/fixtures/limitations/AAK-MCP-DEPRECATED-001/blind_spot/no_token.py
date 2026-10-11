import mcp_utils
from mcp_utils import wrap


def roots(client):
    return wrap(mcp_utils.tidy(client.list_roots()))
