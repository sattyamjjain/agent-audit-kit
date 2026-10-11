import uvicorn
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

app = FastAPI()
mcp = FastMCP("demo")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
