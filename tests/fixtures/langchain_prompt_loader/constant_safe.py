"""Safe: load_prompt with a constant literal path is not flagged."""
from __future__ import annotations

from langchain.prompts import load_prompt  # type: ignore[import-not-found]


def render(query: str) -> str:
    template = load_prompt("templates/research.yaml")
    return template.format(query=query)
