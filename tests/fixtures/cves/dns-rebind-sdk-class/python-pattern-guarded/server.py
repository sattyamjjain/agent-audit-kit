from mcp.server.streamable_http import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Mount

session_manager = StreamableHTTPSessionManager(app=my_server)
app = Starlette(
    routes=[Mount("/mcp", app=session_manager.handle_request)],
    middleware=[(TrustedHostMiddleware, {"allowed_hosts": ["localhost", "127.0.0.1"]})],
)
