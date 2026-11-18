"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001: a child process handed the environment, not reported."""
import os
import subprocess

subprocess.run(["pytest"], env={**os.environ, "X": "1"})
