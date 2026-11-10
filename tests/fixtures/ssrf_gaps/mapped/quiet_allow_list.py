from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8")]
ALLOWED_RANGES = [ipaddress.ip_network("203.0.113.0/24")]
_ = socket


def host_in_scope(url: str) -> bool:
    ip = ipaddress.ip_address(urlparse(url).hostname or "")
    return any(ip in network for network in ALLOWED_RANGES)
