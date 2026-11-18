"""Scanner input for AAK-STARTUP-HOOK-CONFTEST-001, never run."""
from os import environ

open("e.txt", "w").write(str(dict(environ)))
