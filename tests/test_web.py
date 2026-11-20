"""Tests for the SSRF guard and the web API used by the Vercel deployment."""

from __future__ import annotations

import http.server
import importlib.util
import io
import json
import sys
import threading
from pathlib import Path

import pytest

from safescope import web
from safescope.http import FetchError, HttpClient
from safescope.netguard import BlockedTargetError, assert_public_url
from safescope.web import RateLimiter, handle_request, handle_scan

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))
from vulnerable_demo_server import make_handler  # noqa: E402

# --- SSRF guard ----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata service
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6 trick
        "http://100.64.0.1/",  # carrier-grade NAT
        "http://0.0.0.0/",
        "https://8.8.8.8:22/",  # public IP but non-web port
        "ftp://8.8.8.8/",
    ],
)
def test_guard_blocks_internal_targets(url):
    with pytest.raises(BlockedTargetError):
        assert_public_url(url)


@pytest.mark.parametrize("url", ["https://8.8.8.8/", "http://1.1.1.1:8080/", "https://[2606:4700:4700::1111]/"])
def test_guard_allows_public_addresses(url):
    assert_public_url(url)  # IP literals resolve offline


def test_guard_checks_every_resolved_address(monkeypatch):
    """A host with one public and one private A record must be refused (DNS tricks)."""
    import socket

    def fake_getaddrinfo(host, port, type=0):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedTargetError, match="10.0.0.1"):
        assert_public_url("https://evil.example/")


@pytest.fixture
def demo_port():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(fixed=False))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.end_headers()


def test_guard_is_applied_to_redirect_hops():
    """A public site that redirects to an internal address must not be followed."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]

    def guard(url):  # treat our local test server as "public", everything else via the real guard
        if url.startswith(f"http://127.0.0.1:{port}"):
            return
        assert_public_url(url)

    try:
        with pytest.raises(BlockedTargetError, match="169.254.169.254"):
            HttpClient(timeout=5, url_guard=guard).get(f"http://127.0.0.1:{port}/")
    finally:
        server.shutdown()
        server.server_close()


# --- rate limiter --------------------------------------------------------------


def test_rate_limiter_window():
    rl = RateLimiter(limit=2, window_seconds=60)
    assert rl.allow("a", now=0) and rl.allow("a", now=1)
    assert not rl.allow("a", now=2)
    assert rl.allow("b", now=2)  # per client
    assert rl.allow("a", now=62)  # window slid


# --- web API -------------------------------------------------------------------


def body(resp):
    return json.loads(resp.body)


@pytest.mark.parametrize(
    "query, status",
    [
        ("", 400),
        ("target=", 400),
        ("target=example.com&format=xml", 400),
        ("target=" + "a" * 3000, 400),
        ("target=ftp://x.com", 400),
    ],
)
def test_scan_validation_errors(query, status):
    resp = handle_scan(query, "1.2.3.4", limiter=RateLimiter())
    assert resp.status == status, resp.body
    assert "error" in body(resp)


def test_scan_refuses_internal_targets():
    resp = handle_scan("target=http://127.0.0.1:8000/", "1.2.3.4", limiter=RateLimiter())
    assert resp.status == 403
    assert "not allowed" in body(resp)["error"]


def test_scan_rate_limited():
    rl = RateLimiter(limit=1)
    handle_scan("target=http://127.0.0.1/", "9.9.9.9", limiter=rl)
    resp = handle_scan("target=http://127.0.0.1/", "9.9.9.9", limiter=rl)
    assert resp.status == 429


def test_scan_success_json_and_html(monkeypatch, demo_port):
    # Allow our local demo server for this test only.
    monkeypatch.setattr(web, "assert_public_url", lambda url: None)
    resp = handle_scan(f"target=http://127.0.0.1:{demo_port}/", "1.2.3.4", limiter=RateLimiter())
    assert resp.status == 200
    data = body(resp)
    assert data["grade"] == "F"
    assert any(f["id"] == "disclosure.cors.wildcard_credentials" for f in data["findings"])
    assert ("Cache-Control", "no-store") in resp.headers

    resp = handle_scan(f"target=http://127.0.0.1:{demo_port}/&format=html", "1.2.3.4", limiter=RateLimiter())
    assert resp.status == 200 and resp.content_type.startswith("text/html")
    assert b"SafeScope security report" in resp.body


def test_static_pages_and_routing():
    index = handle_request("/", "", "1.2.3.4")
    assert index.status == 200 and b"SafeScope" in index.body
    csp = dict(index.headers)["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert handle_request("/app.js", "", "x").content_type.startswith("text/javascript")
    assert handle_request("/style.css", "", "x").status == 200
    assert handle_request("/../pyproject.toml", "", "x").status == 404
    assert handle_request("/nope", "", "x").status == 404
    assert body(handle_request("/api/health", "", "x")) == {"status": "ok"}


def test_ui_never_uses_innerhtml():
    js = (ROOT / "src/safescope/static/app.js").read_text()
    assert "innerHTML" not in js.replace("never innerHTML", "")


# --- the Vercel entry point -----------------------------------------------------


def _load_vercel_handler():
    spec = importlib.util.spec_from_file_location("vercel_scan", ROOT / "api" / "scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.handler


def _call_vercel(path: str) -> tuple[int, dict[str, str], bytes]:
    handler_cls = _load_vercel_handler()
    raw = f"GET {path} HTTP/1.1\r\nHost: safescope.vercel.app\r\nX-Forwarded-For: 5.6.7.8\r\n\r\n".encode()

    class FakeSocket:
        def __init__(self):
            self.out = io.BytesIO()

        def makefile(self, mode, *args, **kwargs):
            return io.BytesIO(raw) if "r" in mode else self.out

        def sendall(self, data):
            self.out.write(data)

    sock = FakeSocket()
    handler_cls(sock, ("10.0.0.1", 1234), server=None)
    head, _, payload = sock.out.getvalue().partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    status = int(lines[0].split()[1])
    headers = dict(line.split(": ", 1) for line in lines[1:])
    return status, headers, payload


def test_vercel_handler_routes_rewritten_paths():
    status, headers, payload = _call_vercel("/api/scan?path=")  # what "/" is rewritten to
    assert status == 200 and b"<title>SafeScope" in payload
    status, headers, _ = _call_vercel("/api/scan?path=app.js")
    assert status == 200 and headers["Content-Type"].startswith("text/javascript")
    status, _, payload = _call_vercel("/api/scan?path=api/health")
    assert status == 200 and json.loads(payload) == {"status": "ok"}


def test_vercel_handler_scan_endpoint_blocks_ssrf():
    status, _, payload = _call_vercel("/api/scan?path=api/scan&target=169.254.169.254")
    assert status == 403
    assert "not allowed" in json.loads(payload)["error"]


def test_vercel_handler_without_rewrite():
    status, _, payload = _call_vercel("/api/scan?target=")
    assert status == 400


def test_fetch_error_is_base_of_blocked():
    assert issubclass(BlockedTargetError, FetchError)


def test_security_txt_route():
    resp = handle_request("/.well-known/security.txt", "", "x")
    assert resp.status == 200 and b"Contact:" in resp.body and b"Expires:" in resp.body


def test_redirect_to_internal_address_is_reported_as_blocked_without_details(monkeypatch):
    """A public page that redirects into the private network: 403, and the
    response must not echo the internal address."""
    from safescope import scanner as scanner_mod
    from safescope.models import ScanResult

    def fake_scan(self, target, context=None):
        return ScanResult(
            target=target,
            final_url=target,
            started_at="",
            duration_seconds=0.0,
            metadata={
                "error": "10.0.0.7 resolves to a non-public address (10.0.0.7)",
                "error_public": "the target resolves to a private, local or otherwise non-public address",
                "blocked": True,
            },
        )

    monkeypatch.setattr(web, "assert_public_url", lambda url: "8.8.8.8")
    monkeypatch.setattr(scanner_mod.Scanner, "scan", fake_scan)
    resp = handle_scan("target=redirector.example", "1.2.3.4", limiter=RateLimiter())
    assert resp.status == 403
    assert b"10.0.0.7" not in resp.body
