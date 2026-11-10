from app import authorize, principal_var, run


def handle(request: dict) -> dict:
    principal = principal_var.get(None)
    if principal is not None:
        authorize(principal)
    return run(request)
