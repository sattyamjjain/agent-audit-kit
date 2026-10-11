import requests

from guards import validate_safe_url


def fetch(url):
    validate_safe_url(url)
    return requests.get(url)
