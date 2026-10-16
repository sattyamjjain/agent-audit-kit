import requests

from guards import validate_safe_url


def fetch(url):
    validate_safe_url(url)
    # TODO: fetch through a pinned_ip session instead
    return requests.get(url)
