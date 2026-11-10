DENY = "deny"


def run_tool_constant(verdict, tool):
    if verdict == DENY:  # a deny word held in a constant
        return "blocked"
    return tool()


def run_tool_flag(verdict, tool):
    blocked = False
    if verdict == "deny":  # a flag set in the branch
        blocked = True
    if not blocked:
        return tool()
    return "blocked"


def run_ui_action(action, tool):  # a common word, in a file not named for a gate: see web.py
    return tool()
