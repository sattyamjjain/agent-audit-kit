import re

DENY_PATTERNS = [re.compile("DROP TABLE")]


def is_denied(command):
    head = command[0:500]
    return any(p.search(head) for p in DENY_PATTERNS)


def run(command):
    if is_denied(command):
        raise ValueError("denied")
    return command
