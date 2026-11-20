"""Protection against Server-Side Request Forgery (SSRF).

When SafeScope runs as a public web service, a visitor could ask it to "scan"
``http://169.254.169.254/`` (cloud metadata) or ``http://127.0.0.1:6379/`` and
use the server as a proxy into private networks. :func:`assert_public_url` is
called before *every* connection - including each redirect hop and the TLS
handshake - and refuses anything that does not resolve to a public address.

The command line tool does not use the guard by default, because scanning your
own staging server on a private network is a legitimate use there.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from safescope.http import FetchError

ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})


class BlockedTargetError(FetchError):
    """The target resolves to an address that must not be scanned from a public service."""


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def assert_public_host(host: str, port: int) -> None:
    if port not in ALLOWED_PORTS:
        raise BlockedTargetError(f"port {port} is not allowed (allowed: {sorted(ALLOWED_PORTS)})")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"could not resolve {host}: {exc}") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise FetchError(f"could not resolve {host}")
    private = sorted(a for a in addresses if not _is_public(str(a)))
    if private:
        raise BlockedTargetError(f"{host} resolves to a non-public address ({', '.join(map(str, private))})")


def assert_public_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise BlockedTargetError(f"unsupported URL: {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    assert_public_host(parts.hostname, port)
