from pathlib import Path


def execute(path: str, text: str) -> None:
    Path(path).write_text(text)
