from app import require_scope, run, server


@server.call_tool()
async def call(name: str, arguments: dict) -> list:
    require_scope("tools:call")
    return run(name)
