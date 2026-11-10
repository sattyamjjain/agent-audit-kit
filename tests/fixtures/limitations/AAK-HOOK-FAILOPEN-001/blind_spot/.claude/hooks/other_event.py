import json
import sys

data = json.load(sys.stdin)
if data:
    sys.exit(2)
