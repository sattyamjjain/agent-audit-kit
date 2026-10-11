def execute(path: str, text: str) -> None:
    with open(path, "w") as handle:
        handle.write(text)
