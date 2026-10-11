import mcp_utils
from mcp_utils import wrap


def draft(client):
    return wrap(mcp_utils.tidy(client.create_message(messages=[], max_tokens=100)))
