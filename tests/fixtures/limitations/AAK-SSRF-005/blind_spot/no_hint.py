import requests


def fetch(arguments: dict) -> str:
    return requests.get(arguments["url"]).text
