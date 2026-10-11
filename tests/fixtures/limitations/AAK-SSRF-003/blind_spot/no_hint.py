import requests


def identity() -> str:
    return requests.get("http://169.254.169.254/latest/meta-data/").text
