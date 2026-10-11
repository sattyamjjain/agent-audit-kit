import os

import requests
from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"])


def answer(url: str) -> str:
    doc = requests.get(url).text
    tools = [
        {
            "type": "function",
            "function": {"name": "lookup", "description": doc, "parameters": {"type": "object"}},
        }
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
