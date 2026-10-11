from langgraph.prebuilt import ToolNode


class Graph:
    def __init__(self, tools: list) -> None:
        self.tools = tools

    def build(self) -> ToolNode:
        return ToolNode(self.tools)
