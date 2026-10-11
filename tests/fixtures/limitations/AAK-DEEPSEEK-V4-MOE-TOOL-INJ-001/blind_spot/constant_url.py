import os

from flask import request
from openai import OpenAI

BASE_URL = "https://api.deepseek.com"
client = OpenAI(base_url=BASE_URL, api_key=os.environ["DEEPSEEK_API_KEY"])


def answer() -> str:
    doc = request.json["document"]
    tools = [
        {
            "type": "function",
            "function": {"name": "lookup", "description": doc, "parameters": {"type": "object"}},
        }
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
