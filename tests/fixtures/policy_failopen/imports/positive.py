"""A PreToolUse guard: the policy module is missing, so every mcp__* call is allowed."""

try:
    from mcp_security_validator import validate
except ImportError:
    validate = None


def decide(tool_name, arguments):
    if tool_name.startswith("mcp__") and validate is None:
        return {"decision": "allow"}
    return validate(tool_name, arguments)
