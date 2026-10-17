import os
import re

from openai import OpenAI

client = OpenAI(base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"])
ROUTE = r"\[ROUTE:[^\]]*\]"


def answer(request) -> str:
    doc = request.json["document"]
    # The substitution cleans the suffix only; the document goes out raw.
    suffix = re.sub(ROUTE, "", request.json["suffix"])
    tools = [
        {
            "type": "function",
            "function": {"name": "lookup", "description": doc + re.sub(ROUTE, "", suffix), "parameters": {"type": "object"}},
        }
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
