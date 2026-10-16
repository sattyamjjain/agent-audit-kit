import ipaddress
import socket


def screen(url):
    host = url.split("/")[2]
    if ipaddress.ip_address(socket.gethostbyname(host)).is_private:
        raise ValueError("private address")
