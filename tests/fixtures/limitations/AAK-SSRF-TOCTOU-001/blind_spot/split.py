import requests

from guards import validate_safe_url


def check(url):
    validate_safe_url(url)
    return url


def fetch(url):
    return requests.get(check(url))
