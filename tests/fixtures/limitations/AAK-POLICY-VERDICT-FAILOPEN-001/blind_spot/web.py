def apply(action, tool):
    if action == "block":
        return "blocked"
    return tool()
