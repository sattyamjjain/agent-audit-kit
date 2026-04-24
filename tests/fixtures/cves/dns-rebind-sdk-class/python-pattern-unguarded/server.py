from mcp.server.streamable_http import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount

session_manager = StreamableHTTPSessionManager(app=my_server)
app = Starlette(routes=[Mount("/mcp", app=session_manager.handle_request)])
