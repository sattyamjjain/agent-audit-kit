from langchain_core.prompts import load_prompt


def handle(request):
    name = request.json["name"]
    return load_prompt(name)
