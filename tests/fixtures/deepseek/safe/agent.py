"""Safe: DeepSeek tool description routed through sanitiser."""
from __future__ import annotations

from openai import OpenAI

from agent_audit_kit.sanitizers.deepseek import sanitize_tool_description


client = OpenAI(base_url="https://api.deepseek.com/v1", api_key="dummy")


def handle(request) -> dict:
    user_payload = request.json()
    description = sanitize_tool_description(user_payload["tool"]["description"])
    return client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": "go"}],
        tools=[
            {
                "type": "function",
                "function": {"name": "lookup", "description": description},
            }
        ],
    )
