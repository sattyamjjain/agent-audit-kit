from crewai_tools import CodeInterpreterTool, JSONSearchTool, RagTool


def handle(request):
    data = request.json
    CodeInterpreterTool(unsafe_mode=True)
    JSONSearchTool(file_path=data["path"])
    RagTool(url=data["url"])
