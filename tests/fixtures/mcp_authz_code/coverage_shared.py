from app import authorize, run, server


@server.call_tool()
async def call(name: str, arguments: dict) -> list:
    authorize(name)
    return run(name)


@server.read_resource()
async def read(uri: str) -> str:
    authorize(uri)
    return run(uri)


@server.get_prompt()
async def prompt(name: str) -> str:
    authorize(name)
    return run(name)


@server.completion()
async def complete(ref: str) -> list:
    authorize(ref)
    return run(ref)
