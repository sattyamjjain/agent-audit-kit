from crewai_tools import CodeInterpreterTool


def run(request):
    data = request.json
    CodeInterpreterTool(unsafe_mode=True)
    return data
