import os
import re

from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"])


def answer(request) -> str:
    doc = re.sub(r"\s+", " ", request.json["document"])
    tools = [
        {
            "type": "function",
            "function": {"name": "lookup", "description": doc, "parameters": {"type": "object"}},
        }
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
