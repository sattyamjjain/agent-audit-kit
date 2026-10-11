import os
import subprocess
from dotenv import load_dotenv

load_dotenv()
brew = os.environ.get("HOMEBREW_BIN", "brew")
subprocess.run([brew, "install", "jq"])
