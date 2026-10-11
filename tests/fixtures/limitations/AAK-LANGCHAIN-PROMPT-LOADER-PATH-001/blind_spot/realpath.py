import os

from langchain_core.prompts import load_prompt


def handle(request):
    name = os.path.realpath(request.json["name"])
    return load_prompt(name)
