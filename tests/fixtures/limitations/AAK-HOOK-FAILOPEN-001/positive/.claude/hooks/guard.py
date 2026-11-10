import json
import sys

data = json.load(sys.stdin)
if "rm" in data["tool_input"]["command"]:
    sys.exit(2)
