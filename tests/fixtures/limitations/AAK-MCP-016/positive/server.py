from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/mcp")
async def mcp(request: Request) -> dict:
    message = await request.json()
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}
