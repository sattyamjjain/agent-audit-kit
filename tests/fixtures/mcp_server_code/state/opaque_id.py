def resume(params: dict, store) -> bool:
    pending = store.lookup(params["requestState"])
    return pending is not None and pending.confirmed
