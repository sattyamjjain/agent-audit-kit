from app import run, server


@server.call_tool()
async def call(name: str, arguments: dict) -> list:
    return run(name)


@server.read_resource()
async def read(uri: str) -> str:
    return run(uri)
