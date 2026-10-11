from langchain_core.prompts import load_prompt


def handle(name: str):
    return load_prompt("prompts/" + name)
