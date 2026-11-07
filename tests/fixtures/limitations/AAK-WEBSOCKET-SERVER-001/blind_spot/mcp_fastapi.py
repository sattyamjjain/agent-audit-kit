from fastapi import FastAPI, WebSocket

app = FastAPI()


@app.websocket("/ws")
async def endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    # websockets is not what serves this.
