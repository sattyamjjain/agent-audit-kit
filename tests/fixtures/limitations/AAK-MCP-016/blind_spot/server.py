from fastapi import FastAPI, Request

app = FastAPI()


async def read_message(request: Request) -> dict:
    return await request.json()


@app.post("/mcp")
async def mcp(request: Request) -> dict:
    message = await read_message(request)
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}
