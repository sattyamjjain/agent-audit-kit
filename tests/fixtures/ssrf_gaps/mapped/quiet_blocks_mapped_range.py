from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED = [ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8")]
ALLOWED_RANGES = [ipaddress.ip_network("203.0.113.0/24")]
_ = socket


SIX = ipaddress.ip_network("::ffff:0:0/96")


def validate_url(url: str) -> bool:
    ip = ipaddress.ip_address(urlparse(url).hostname or "")
    return not (ip in SIX or any(ip in network for network in BLOCKED))
