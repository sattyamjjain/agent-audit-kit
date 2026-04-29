"""Vulnerable: load_prompt fed by request body without anchoring."""
from __future__ import annotations

from langchain.prompts import load_prompt  # type: ignore[import-not-found]


def render(request) -> str:
    body = request.json()
    template = load_prompt(body["template_path"])
    return template.format(query=body["query"])
