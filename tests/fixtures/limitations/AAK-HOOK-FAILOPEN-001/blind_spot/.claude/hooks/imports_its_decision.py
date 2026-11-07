import json
import sys

from policy import evaluate

print(json.dumps(evaluate(json.load(sys.stdin))))
