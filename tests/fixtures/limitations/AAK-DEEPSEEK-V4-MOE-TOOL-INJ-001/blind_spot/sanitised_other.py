import os

from openai import OpenAI

from agent_audit_kit.sanitizers.deepseek import sanitize_tool_description

client = OpenAI(base_url="https://api.deepseek.com", api_key=os.environ["DEEPSEEK_API_KEY"])


def answer(request) -> str:
    # The sanitiser cleans the name; the description goes out raw.
    name = sanitize_tool_description(request.json["name"])
    doc = request.json["document"]
    tools = [
        {
            "type": "function",
            "function": {"name": name, "description": doc, "parameters": {"type": "object"}},
        }
    ]
    reply = client.chat.completions.create(model="deepseek-chat", messages=[], tools=tools)
    return reply.choices[0].message.content
