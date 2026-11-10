"""The bearer token below is never checked, and the rule takes the word for the check."""

import asyncio

import websockets


async def handler(connection: object) -> None:
    await asyncio.sleep(0)


async def main() -> None:
    async with websockets.serve(handler, "127.0.0.1", 8000):
        await asyncio.Future()
