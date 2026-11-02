import subprocess


def start() -> subprocess.Popen:
    return subprocess.Popen(["deno", "run", "-A", "server.ts"])
