import ipaddress
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("10.0.0.0/8")]


def validate_url(url: str) -> None:
    host = urlparse(url).hostname or ""
    ip = ipaddress.ip_address(host)
    if any(ip in network for network in BLOCKED):
        raise ValueError("blocked")
