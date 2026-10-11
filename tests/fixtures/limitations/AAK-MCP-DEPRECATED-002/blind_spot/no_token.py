def draft(client):
    return client.create_message(messages=[], max_tokens=100)
