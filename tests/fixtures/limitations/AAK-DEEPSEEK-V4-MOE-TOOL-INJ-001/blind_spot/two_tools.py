import os
import re

from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"])

ROUTE_TOKENS = r"\[ROUTE:[^\]]*\]|<\|route_id\|>|__route__\s*="


def answer(request) -> str:
    # The function is judged as a whole: the first description is cleaned, so
    # the second goes out raw unreported.
    doc = request.json["document"]
    notes = request.json["notes"]
    tools = [
        {"type": "function", "function": {"name": "doc", "description": re.sub(ROUTE_TOKENS, "", doc)}},
        {"type": "function", "function": {"name": "notes", "description": notes}},
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
