from langchain.tools import BaseTool


class ToolBase(BaseTool):
    timeout: float = 10.0
