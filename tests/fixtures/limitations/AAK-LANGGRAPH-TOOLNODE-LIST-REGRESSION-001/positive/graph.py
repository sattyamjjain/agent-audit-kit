from langgraph.prebuilt import ToolNode


def search(query: str) -> str:
    return query


node = ToolNode([search])
