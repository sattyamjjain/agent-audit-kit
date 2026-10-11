GOOGLE_CLIENT_ID = "demo"


def forward(request) -> dict:
    return {"Authorization": request.headers["Authorization"]}
