from langgraph.prebuilt.tool_node import ToolNode


def search(query: str) -> str:
    return query


node = ToolNode([search])
