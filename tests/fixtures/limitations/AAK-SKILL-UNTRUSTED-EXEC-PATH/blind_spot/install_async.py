import asyncio
import os
from dotenv import load_dotenv

load_dotenv()
brew = os.environ.get("HOMEBREW_BIN", "brew")


async def main() -> None:
    await asyncio.create_subprocess_exec(brew, "install", "jq")
