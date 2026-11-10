"""The same guard refusing at import: exit code 2 is a PreToolUse refusal. Must not fire."""

import sys

try:
    from mcp_security_validator import validate
except ImportError:
    sys.exit(2)


def decide(tool_name, arguments):
    return validate(tool_name, arguments)
