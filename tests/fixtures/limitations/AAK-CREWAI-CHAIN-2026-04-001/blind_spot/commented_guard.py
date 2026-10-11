from crewai_tools import CodeInterpreterTool, JSONSearchTool, RagTool


def handle(request):
    data = request.json
    # assert_codeinterp_safe_mode(False)
    CodeInterpreterTool(unsafe_mode=True)
    JSONSearchTool(file_path=data["path"])
    RagTool(url=data["url"])
