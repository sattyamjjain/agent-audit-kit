from app import authorize, principal_var, run


def handle(request: dict) -> dict:
    principal = principal_var.get(None)
    if principal is None:
        raise PermissionError("no principal")
    authorize(principal)
    return run(request)
