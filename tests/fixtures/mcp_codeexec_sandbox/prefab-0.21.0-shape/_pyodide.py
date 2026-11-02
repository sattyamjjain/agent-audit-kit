import shutil
import subprocess
from pathlib import Path

RUNNER_JS = Path(__file__).parent / "runner.js"


def start() -> subprocess.Popen:
    deno = shutil.which("deno") or "deno"
    return subprocess.Popen(
        [
            deno,
            "run",
            "--unstable-detect-cjs",
            "--no-prompt",
            "--allow-read",
            "--allow-write",
            "--allow-net=cdn.jsdelivr.net:443",
            str(RUNNER_JS),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
