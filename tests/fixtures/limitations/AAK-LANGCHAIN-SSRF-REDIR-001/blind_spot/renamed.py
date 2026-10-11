import requests

from guards import assert_public_url


def fetch(url):
    assert_public_url(url)
    return requests.get(url)
