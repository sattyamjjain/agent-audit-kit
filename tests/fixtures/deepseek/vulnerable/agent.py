"""Vulnerable: DeepSeek tool description sourced from request body
without sanitisation."""
from __future__ import annotations

from openai import OpenAI


client = OpenAI(base_url="https://api.deepseek.com/v1", api_key="dummy")


def handle(request) -> dict:
    user_payload = request.json()  # taint source
    description = user_payload["tool"]["description"]
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
