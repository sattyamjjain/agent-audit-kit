from mcp import StdioServerParameters


def build(spec):
    return StdioServerParameters(command=spec["cmd"], args=spec["args"])


def handler(request):
    return build(request.json())


def pick_command(body):
    return body["cmd"]


def build_from_helper(body):
    cmd = pick_command(body)
    return StdioServerParameters(command=cmd, args=[])


class Launcher:
    def __init__(self, body):
        self.cfg = body

    def build(self):
        return StdioServerParameters(command=self.cfg["cmd"], args=[])
