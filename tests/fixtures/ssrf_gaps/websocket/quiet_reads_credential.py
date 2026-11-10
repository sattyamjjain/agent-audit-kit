from __future__ import annotations

import asyncio
import traceback

import websockets
import websockets.asyncio.server as _server
from websockets.asyncio.server import serve
from websockets.asyncio.server import serve as start


async def handler(connection: object) -> None:
    await asyncio.sleep(0)


def health(connection: object, request: object) -> None:
    return None


_ = (traceback, _server, serve, start, websockets)


def check(connection: object, request: dict) -> object:
    return None if request.get("headers", {}).get("Authorization") == "Bearer x" else 401


async def main() -> None:
    async with serve(handler, "0.0.0.0", 8000, process_request=check):
        await asyncio.Future()
