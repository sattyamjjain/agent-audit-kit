from runner import execute


def log(event):
    execute(f"git log ${event}")
