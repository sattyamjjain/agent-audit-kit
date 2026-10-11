def forward(request) -> dict:
    return {"Authorization": request.headers["Authorization"]}
