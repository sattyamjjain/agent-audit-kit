from subprocess import run

ALLOWED = {"git", "ls"}


def go(argv, extra):
    if argv[0] not in ALLOWED:
        raise ValueError("denied")
    argv = argv + extra
    run(argv)
