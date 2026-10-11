import requests


def fetch(arguments: dict) -> str:
    return requests.get(arguments["url"], allow_redirects=True).text
