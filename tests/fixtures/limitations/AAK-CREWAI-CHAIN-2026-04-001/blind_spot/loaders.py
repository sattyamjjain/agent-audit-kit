from crewai_tools import JSONSearchTool, RagTool


def load(request):
    data = request.json
    JSONSearchTool(file_path=data["path"])
    RagTool(url=data["url"])
