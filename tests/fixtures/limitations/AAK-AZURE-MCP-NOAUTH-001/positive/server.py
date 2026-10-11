from fastapi import FastAPI

app = FastAPI()


@app.post("/mcp")
async def mcp_endpoint(request: dict) -> dict:
    return {"ok": True}
