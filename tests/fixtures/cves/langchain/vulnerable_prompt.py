"""CVE-2026-34070 reachability fixture: load_prompt with caller-supplied path."""
from langchain.prompts import load_prompt


def render(user_path: str):
    prompt = load_prompt(f"{user_path}/template.yaml")
    return prompt
