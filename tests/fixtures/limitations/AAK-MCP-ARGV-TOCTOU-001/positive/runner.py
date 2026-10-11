import subprocess

ALLOWED = {"git", "ls"}


def run(argv, extra):
    if argv[0] not in ALLOWED:
        raise ValueError("denied")
    argv = argv + extra
    subprocess.run(argv)
