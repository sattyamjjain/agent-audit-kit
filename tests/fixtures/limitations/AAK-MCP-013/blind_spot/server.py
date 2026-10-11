from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.fastmcp import FastMCP

app = FastAPI()
mcp = FastMCP("demo")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
