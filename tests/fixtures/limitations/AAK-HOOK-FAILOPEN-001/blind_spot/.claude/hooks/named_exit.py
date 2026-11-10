import json
import sys

REFUSE = 2

data = json.load(sys.stdin)
if "rm" in data["tool_input"]["command"]:
    sys.exit(REFUSE)
