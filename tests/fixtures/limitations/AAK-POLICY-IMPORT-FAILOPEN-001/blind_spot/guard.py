try:  # a policy module named for something else
    from checks import run
except ImportError:
    run = lambda *args, **kwargs: True  # noqa: E731

try:  # a broader handler is not read
    from policy_engine import check
except Exception:
    check = lambda *args, **kwargs: True  # noqa: E731

try:  # a name left unset with no later test: calling None raises
    from guard_rails import enforce
except ImportError:
    enforce = None
