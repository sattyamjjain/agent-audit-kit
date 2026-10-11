from azure.identity import DefaultAzureCredential
from fastapi import FastAPI

app = FastAPI()
credential = DefaultAzureCredential()


@app.post("/mcp")
async def mcp_endpoint(request: dict) -> dict:
    token = credential.get_token("https://management.azure.com/.default")
    return {"ok": bool(token)}
