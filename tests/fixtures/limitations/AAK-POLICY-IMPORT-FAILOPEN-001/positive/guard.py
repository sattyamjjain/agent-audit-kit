try:
    from policy_engine import check
except ImportError:
    check = lambda *args, **kwargs: True  # noqa: E731
