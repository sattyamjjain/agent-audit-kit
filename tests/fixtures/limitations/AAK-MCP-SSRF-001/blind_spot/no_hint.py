import requests


def summarize(url: str) -> str:
    return requests.get(url).text
