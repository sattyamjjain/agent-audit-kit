from app import require_scope, run, server


@server.call_tool()
async def call(name: str, arguments: dict) -> list:
    require_scope("tools:call")
    return run(name)


@server.read_resource()
async def read(uri: str) -> str:
    return run(uri)


@server.get_prompt()
async def prompt(name: str) -> str:
    return run(name)
