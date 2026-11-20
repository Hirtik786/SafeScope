"""Protection against Server-Side Request Forgery (SSRF) and DNS rebinding.

When SafeScope runs as a public web service, a visitor could ask it to "scan"
``http://169.254.169.254/`` (cloud metadata) or ``http://127.0.0.1:6379/`` and
use the server as a proxy into private networks.

:func:`assert_public_url` is the guard. It is called before *every* connection
(each redirect hop and the TLS handshake), resolves the host once, refuses the
target if *any* resolved address is not public, and returns the validated
address. The caller then connects to exactly that address while keeping the
original host name for the ``Host`` header, TLS SNI and certificate checks.
Connecting by name instead would let the operating system resolve the name a
second time, and an attacker controlling DNS could answer ``127.0.0.1`` on the
second lookup (DNS rebinding).

The command line tool does not use the guard by default, because scanning your
own staging server on a private network is a legitimate use there
(``--public-only`` turns it on).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from safescope.http import FetchError

ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})


class BlockedTargetError(FetchError):
    """The target resolves to an address that must not be scanned from a public service.

    ``str(exc)`` carries the details (useful in a terminal); ``public_message``
    is safe to return to anonymous API users because it names no addresses.
    """

    def __init__(self, message: str, public_message: str | None = None) -> None:
        super().__init__(message)
        self.public_message = public_message or message


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])  # drop an IPv6 zone id such as fe80::1%eth0
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public_host(host: str, port: int) -> str:
    """Resolve ``host`` once and return an address that is safe to connect to.

    Every address in the answer must be public: a name that answers both a
    public and a private address is refused, because the operating system could
    pick either one.
    """
    if port not in ALLOWED_PORTS:
        message = f"port {port} is not allowed (allowed: {', '.join(map(str, sorted(ALLOWED_PORTS)))})"
        raise BlockedTargetError(message)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise FetchError(f"could not resolve {host}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FetchError(f"could not resolve {host}")
    private = [a for a in addresses if not _is_public(a)]
    if private:
        raise BlockedTargetError(
            f"{host} resolves to a non-public address ({', '.join(private)})",
            public_message="the target resolves to a private, local or otherwise non-public address",
        )
    return addresses[0]  # the system's preferred order


def assert_public_url(url: str) -> str:
    """Guard for :class:`~safescope.http.HttpClient`: validate ``url`` and return the address to use."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise BlockedTargetError(f"unsupported URL: {url!r}", public_message="unsupported URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:  # e.g. https://example.com:99999/
        raise BlockedTargetError(f"invalid port in {url!r}", public_message="invalid port") from exc
    return resolve_public_host(parts.hostname, port)
