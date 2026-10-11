from langchain_core.prompts.loading import load_prompt


def handle(request):
    name = request.json["name"]
    return load_prompt(name)
