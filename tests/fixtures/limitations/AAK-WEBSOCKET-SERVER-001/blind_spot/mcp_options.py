import asyncio

import websockets


OPTIONS: dict = {}


async def handler(connection: object) -> None:
    await asyncio.sleep(0)


async def main() -> None:
    async with websockets.serve(handler, "127.0.0.1", 8000, **OPTIONS):
        await asyncio.Future()
