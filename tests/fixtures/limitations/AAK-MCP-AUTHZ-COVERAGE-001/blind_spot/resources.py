from app import run, server


@server.read_resource()  # handlers split across files are not compared
async def read(uri: str) -> str:
    return run(uri)
