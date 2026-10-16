import requests

from netcheck import screen


def fetch(url):
    screen(url)
    return requests.get(url)
