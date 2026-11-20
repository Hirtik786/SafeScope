from __future__ import annotations

import pytest

from safescope.context import ScanContext
from safescope.http import FetchError, Headers, HttpClient, Response
from safescope.tls import TLSInfo


def make_response(
    url: str,
    status: int = 200,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    body: bytes = b"",
    chain: list[tuple[int, str]] | None = None,
) -> Response:
    pairs = list(headers.items()) if isinstance(headers, dict) else list(headers or [])
    return Response(
        url=url,
        status=status,
        reason="OK",
        headers=Headers.from_pairs(pairs),
        body=body,
        redirect_chain=chain or [],
    )


class FakeClient(HttpClient):
    """Serves canned responses; unknown URLs raise FetchError like a dead host."""

    def __init__(self, routes: dict[str, Response | Exception]) -> None:
        super().__init__(timeout=1)
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url: str, follow_redirects: bool = True) -> Response:
        self.calls.append(url)
        hit = self.routes.get(url)
        if hit is None:
            raise FetchError(f"connection refused: {url}")
        if isinstance(hit, Exception):
            raise hit
        return hit


def no_tls(host: str, port: int, timeout: float) -> TLSInfo:
    return TLSInfo(host=host, port=port, error="not tested")


@pytest.fixture
def make_ctx():
    def _make(target: str, routes: dict[str, Response | Exception], tls=no_tls) -> ScanContext:
        return ScanContext(target, client=FakeClient(routes), tls_inspector=tls)

    return _make


GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Server": "nginx",
}


def pytest_addoption(parser):
    parser.addoption("--run-network", action="store_true", help="run tests that reach real websites")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-network"):
        return
    skip = pytest.mark.skip(reason="needs internet: use --run-network")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)
