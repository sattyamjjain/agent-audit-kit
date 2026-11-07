import ipaddress
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("10.0.0.0/8")]
OTHER_NAME = [ipaddress.ip_network("169.254.0.0/16")]


def _matches(ip: object) -> bool:
    return any(ip in network for network in BLOCKED)


def address_as_a_parameter(url: str) -> None:
    if _matches(ipaddress.ip_address(urlparse(url).hostname or "")):
        raise ValueError("blocked")


def list_under_another_name(url: str) -> None:
    ip = ipaddress.ip_address(urlparse(url).hostname or "")
    for network in OTHER_NAME:
        if ip in network:
            raise ValueError("no")


def loopback_and_link_local_only(url: str) -> None:
    ip = ipaddress.ip_address(urlparse(url).hostname or "")
    if ip.is_loopback or ip.is_link_local:
        raise ValueError("blocked")


def subnet_of(url: str) -> None:
    ip = ipaddress.ip_network(urlparse(url).hostname or "")
    if ip.subnet_of(BLOCKED[0]):
        raise ValueError("blocked")
