from fastapi import APIRouter, Depends

router = APIRouter()


def verify_api_key() -> str:
    return "key"


@router.post("/mcp")
async def mcp_endpoint(key: str = Depends(verify_api_key)) -> dict:
    return {"ok": True}


@router.post("/mcp_message")
async def mcp_message(request: dict) -> dict:
    return {"ok": True}
