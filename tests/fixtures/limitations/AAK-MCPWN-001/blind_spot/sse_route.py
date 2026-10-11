from fastapi import APIRouter, Depends

router = APIRouter()


def get_current_user() -> str:
    return "user"


@router.post("/mcp")
async def mcp_endpoint(user: str = Depends(get_current_user)) -> dict:
    return {"ok": True, "user": user}


@router.post("/mcp/sse")
async def mcp_sse(request: dict) -> dict:
    return {"ok": True}
