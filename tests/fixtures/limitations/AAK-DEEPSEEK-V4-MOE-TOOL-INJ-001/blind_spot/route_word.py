import os
import re

from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"])


def answer(request) -> str:
    # Drops the lower-case word only: `[ROUTE: expert_7]` goes through as is.
    doc = re.sub(r"route", "path", request.json["document"])
    tools = [
        {
            "type": "function",
            "function": {"name": "lookup", "description": doc, "parameters": {"type": "object"}},
        }
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
