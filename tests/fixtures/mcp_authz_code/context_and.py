from app import allowed, principal_var, run


def handle(request: dict) -> dict:
    principal = principal_var.get(None)
    if principal and not allowed(principal):
        raise PermissionError("no")
    return run(request)
