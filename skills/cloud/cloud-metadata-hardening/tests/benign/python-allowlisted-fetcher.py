import ipaddress
import socket
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"images.example.com", "cdn.example.com"}
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def safe_fetch(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("destination is not allowed")

    resolved_ips = {
        ipaddress.ip_address(result[4][0])
        for result in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    }
    if any(any(ip in network for network in BLOCKED_NETWORKS) for ip in resolved_ips):
        raise ValueError("destination resolves to a blocked network")

    response = requests.get(url, timeout=5, allow_redirects=False)
    response.raise_for_status()
    return response.content
