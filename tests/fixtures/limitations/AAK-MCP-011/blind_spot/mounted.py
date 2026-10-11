from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

app = FastAPI()
mcp = FastMCP("demo")
app.mount("/mcp", mcp.streamable_http_app())
