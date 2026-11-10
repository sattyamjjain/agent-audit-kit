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


async def on_message(connection: object) -> None:
    try:
        await asyncio.sleep(0)
    except Exception:
        await connection.send(traceback.format_exc())
