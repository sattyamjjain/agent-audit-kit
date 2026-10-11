import os

from langchain_core.prompts import load_prompt

PROMPTS = "prompts"


def handle(name: str):
    return load_prompt(os.path.join(PROMPTS, name))
