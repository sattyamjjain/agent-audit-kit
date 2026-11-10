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


class Server:
    def __init__(self, host: str = "0.0.0.0") -> None:
        self._host = host

    async def run(self) -> None:
        async with serve(handler, self._host, 8000, origins=["https://app.example.com"]):
            await asyncio.Future()
