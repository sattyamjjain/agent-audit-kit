from fastmcp import FastMCP

from providers import generative_ui

mcp = FastMCP("dashboards")
mcp.add_provider(generative_ui())
