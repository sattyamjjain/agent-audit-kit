def run_tool(verdict, tool):
    if verdict == "deny":
        return "blocked"
    return tool()
