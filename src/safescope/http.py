"""A tiny, dependency-free HTTP client tailored to passive security checks.

Only ``GET``/``HEAD`` requests are made, redirects are followed manually so the
whole chain can be inspected, and response bodies are capped so scanning a
large page never consumes much memory.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 10
MAX_BODY_BYTES = 256 * 1024
USER_AGENT = "SafeScope/{version} (+https://github.com/Karim-Bazooka/SafeScope)"


class FetchError(Exception):
    """Raised when a URL cannot be fetched at all (DNS, TCP, TLS, timeout...)."""


class CertificateError(FetchError):
    """The TLS certificate could not be verified (self-signed, expired, wrong host...)."""


def pinned_connector(ip: str) -> Callable[..., socket.socket]:
    """A replacement for ``socket.create_connection`` that ignores the host name
    it is given and connects to ``ip`` instead (same port, timeout and source)."""

    def create_connection(
        address: tuple[str, int],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        *args: object,
        **kwargs: object,
    ) -> socket.socket:
        return socket.create_connection((ip, address[1]), timeout, source_address)

    return create_connection


@dataclass
class Headers:
    """Case-insensitive, multi-value header container."""

    items: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[str, str]]) -> Headers:
        return cls([(k, v) for k, v in pairs])

    def get(self, name: str, default: str | None = None) -> str | None:
        lname = name.lower()
        for key, value in self.items:
            if key.lower() == lname:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [v for k, v in self.items if k.lower() == lname]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get(name) is not None


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: Headers
    body: bytes = b""
    redirect_chain: list[tuple[int, str]] = field(default_factory=list)
    """``(status, url)`` for every hop *before* the final response."""

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower()

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class HttpClient:
    """Synchronous HTTP client. Swap it out in tests via :class:`ScanContext`."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        verify_tls: bool = True,
        user_agent: str | None = None,
        url_guard: Callable[[str], str | None] | None = None,
    ) -> None:
        from safescope._version import __version__

        self.timeout = timeout
        self.verify_tls = verify_tls
        self.user_agent = user_agent or USER_AGENT.format(version=__version__)
        #: Called with every URL (including redirect hops) before connecting.
        #: It raises FetchError to refuse the URL, or returns the IP address the
        #: connection must use (DNS pinning, see safescope.netguard), or None to
        #: let the operating system resolve the name as usual.
        self.url_guard = url_guard

    def _ssl_context(self) -> ssl.SSLContext:
        if self.verify_tls:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request_once(self, url: str, method: str = "GET") -> Response:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FetchError(f"unsupported URL: {url!r}")
        pinned_ip = self.url_guard(url) if self.url_guard is not None else None
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                parts.hostname, parts.port, timeout=self.timeout, context=self._ssl_context()
            )
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=self.timeout)
        if pinned_ip is not None:
            # Connect to the validated address. http.client still uses the host
            # name for the Host header, TLS SNI and certificate verification.
            conn._create_connection = pinned_connector(pinned_ip)  # type: ignore[attr-defined]

        try:
            conn.request(
                method,
                path,
                headers={
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            body = resp.read(MAX_BODY_BYTES) if method != "HEAD" else b""
            return Response(
                url=url,
                status=resp.status,
                reason=resp.reason,
                headers=Headers.from_pairs(resp.getheaders()),
                body=body,
            )
        except ssl.SSLCertVerificationError as exc:
            raise CertificateError(f"certificate verification failed: {exc.verify_message or exc}") from exc
        except ssl.SSLError as exc:
            raise FetchError(f"TLS error: {exc}") from exc
        except TimeoutError as exc:
            raise FetchError(f"timed out after {self.timeout:g}s") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(str(exc) or exc.__class__.__name__) from exc
        finally:
            conn.close()

    def get(self, url: str, follow_redirects: bool = True) -> Response:
        chain: list[tuple[int, str]] = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            resp = self.request_once(current)
            location = resp.headers.get("Location")
            if follow_redirects and resp.status in (301, 302, 303, 307, 308) and location:
                chain.append((resp.status, current))
                current = urljoin(current, location)
                continue
            resp.redirect_chain = chain
            return resp
        raise FetchError(f"too many redirects (>{MAX_REDIRECTS}) starting at {url}")
