"""The same guard denying when the policy module is missing. This one must not fire."""

try:
    from mcp_security_validator import validate
except ImportError:
    validate = None


def decide(tool_name, arguments):
    if validate is None:
        return {"decision": "deny"}
    return validate(tool_name, arguments)
