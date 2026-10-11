from openclaw import OpenClawAgent


def build(request):
    return OpenClawAgent(role=request.json["role"])
