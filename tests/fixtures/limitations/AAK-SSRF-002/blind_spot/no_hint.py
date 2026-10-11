import requests


def status() -> str:
    return requests.get("http://localhost:9000/admin").text
