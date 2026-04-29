"""Safe: load_prompt fed by request body but anchored via path_under_root."""
from __future__ import annotations

from langchain.prompts import load_prompt  # type: ignore[import-not-found]

from agent_audit_kit.checks import path_under_root


PROMPT_ROOT = "/srv/agent/prompts"


def render(request) -> str:
    body = request.json()
    safe_path = path_under_root(body["template_path"], root=PROMPT_ROOT)
    template = load_prompt(str(safe_path))
    return template.format(query=body["query"])
