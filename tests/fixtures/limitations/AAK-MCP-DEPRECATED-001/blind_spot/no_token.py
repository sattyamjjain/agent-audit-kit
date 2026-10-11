from mcp_utils import wrap


def roots(client):
    return wrap(client.list_roots())
