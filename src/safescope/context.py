"""Shared, cached state for one scan.

Checks never talk to the network directly; they ask the context. That keeps the
number of requests small (each URL is fetched at most once) and makes every
check trivially testable by injecting a fake client.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from safescope.http import CertificateError, FetchError, HttpClient, Response
from safescope.tls import TLSInfo, inspect_tls


def normalize_target(raw: str) -> str:
    """Turn user input like ``example.com`` into ``https://example.com/``."""
    value = raw.strip()
    if not value:
        raise ValueError("target must not be empty")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"only http:// and https:// targets are supported, got {parts.scheme!r}")
    if not parts.hostname:
        raise ValueError(f"could not find a host name in {raw!r}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


_MISSING = object()


@dataclass
class ScanContext:
    target: str
    client: HttpClient = field(default_factory=HttpClient)
    tls_inspector: Callable[[str, int, float], TLSInfo] = inspect_tls
    _cache: dict[tuple[str, bool], Response | FetchError] = field(default_factory=dict, repr=False)
    _tls: object = field(default=_MISSING, repr=False)
    insecure_fallback: bool = False
    """Set when an untrusted certificate forced us to fetch without verification.
    The TLS check reports the certificate problem; other checks still run."""

    def __post_init__(self) -> None:
        self.target = normalize_target(self.target)

    # -- URL helpers -------------------------------------------------------
    @property
    def host(self) -> str:
        host = urlsplit(self.target).hostname
        assert host is not None  # guaranteed by normalize_target
        return host

    @property
    def scheme(self) -> str:
        return urlsplit(self.target).scheme

    @property
    def port(self) -> int:
        parts = urlsplit(self.target)
        return parts.port or (443 if parts.scheme == "https" else 80)

    def https_url(self) -> str:
        parts = urlsplit(self.target)
        netloc = parts.netloc
        if parts.scheme == "http" and parts.port in (None, 80):
            netloc = parts.hostname or netloc
        return urlunsplit(("https", netloc, parts.path, parts.query, ""))

    def http_url(self) -> str:
        parts = urlsplit(self.target)
        netloc = parts.netloc
        if parts.scheme == "https" and parts.port in (None, 443):
            netloc = parts.hostname or netloc
        return urlunsplit(("http", netloc, parts.path, parts.query, ""))

    # -- Fetching ----------------------------------------------------------
    def fetch(self, url: str, follow_redirects: bool = True) -> Response:
        """Fetch ``url`` once per scan; errors are cached and re-raised too."""
        key = (url, follow_redirects)
        if key not in self._cache:
            try:
                self._cache[key] = self.client.get(url, follow_redirects=follow_redirects)
            except CertificateError:
                try:
                    self._cache[key] = self._insecure_client().get(url, follow_redirects=follow_redirects)
                    self.insecure_fallback = True
                except FetchError as exc:
                    self._cache[key] = exc
            except FetchError as exc:
                self._cache[key] = exc
        cached = self._cache[key]
        if isinstance(cached, FetchError):
            raise cached
        return cached

    def _insecure_client(self) -> HttpClient:
        return HttpClient(
            timeout=self.client.timeout,
            verify_tls=False,
            user_agent=self.client.user_agent,
            url_guard=self.client.url_guard,
        )

    def main_response(self) -> Response:
        """The page as a visitor sees it (redirects followed)."""
        return self.fetch(self.target)

    def fetch_path(self, path: str) -> Response:
        """Fetch a path relative to the final origin, e.g. ``/.well-known/security.txt``."""
        base = self.main_response().url
        return self.fetch(urljoin(base, path))

    def tls_info(self) -> TLSInfo:
        if self._tls is _MISSING:
            if self.client.url_guard is not None:
                self.client.url_guard(self.https_url())
            self._tls = self.tls_inspector(self.host, self.port if self.scheme == "https" else 443,
                                           self.client.timeout)
        assert isinstance(self._tls, TLSInfo)
        return self._tls
