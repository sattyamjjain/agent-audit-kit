from app import check_access, rows, server


@server.call_tool()
async def call(name: str, arguments: dict) -> list:
    org = arguments["org_id"]
    check_access(org)
    return rows(org)
