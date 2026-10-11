from mcp_utils import wrap


def draft(client):
    return wrap(client.create_message(messages=[], max_tokens=100))
