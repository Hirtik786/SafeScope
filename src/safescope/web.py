"""Web API used by the Vercel deployment (``api/scan.py``) and ``safescope serve``.

``GET /api/scan?target=example.com&format=json`` → JSON result
``GET /api/scan?target=example.com&format=html`` → full HTML report

Because this is reachable by anyone on the internet it is hardened:
SSRF guard on every connection, short timeouts, per-IP rate limiting and
strict security headers on every response.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs

from safescope.context import ScanContext, normalize_target
from safescope.http import HttpClient
from safescope.netguard import BlockedTargetError, assert_public_url
from safescope.reporters import render_html, render_json
from safescope.scanner import Scanner

WEB_TIMEOUT = 6.0
MAX_TARGET_LENGTH = 2048

API_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
]
# The generated HTML report contains a small inline script (filters) and inline styles.
REPORT_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
]

SECURITY_TXT = (
    "Contact: https://github.com/Karim-Bazooka/SafeScope/security/advisories/new\n"
    "Expires: 2027-12-31T23:59:59Z\n"
    "Preferred-Languages: en, ar\n"
    "Policy: https://github.com/Karim-Bazooka/SafeScope/blob/main/SECURITY.md\n"
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}
PAGE_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("X-Frame-Options", "DENY"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ),
]


@dataclass
class RateLimiter:
    """Sliding-window limiter. In-memory, so per instance - good enough to stop casual abuse."""

    limit: int = 10
    window_seconds: float = 60.0
    _hits: dict[str, deque[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > self.window_seconds:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            if len(self._hits) > 10_000:  # bound memory
                self._hits = {k: v for k, v in self._hits.items() if v}
            return True


RATE_LIMITER = RateLimiter()


@dataclass
class WebResponse:
    status: int
    content_type: str
    body: bytes
    headers: list[tuple[str, str]] = field(default_factory=list)


def _error(status: int, message: str) -> WebResponse:
    body = json.dumps({"error": message}).encode()
    return WebResponse(status, "application/json; charset=utf-8", body, list(API_SECURITY_HEADERS))


def handle_scan(query: str, client_ip: str, limiter: RateLimiter = RATE_LIMITER) -> WebResponse:
    params = parse_qs(query, keep_blank_values=True)
    raw_target = (params.get("target") or [""])[0].strip()
    fmt = (params.get("format") or ["json"])[0]
    if not raw_target:
        return _error(400, "missing 'target' parameter, e.g. /api/scan?target=example.com")
    if len(raw_target) > MAX_TARGET_LENGTH:
        return _error(400, "target is too long")
    if fmt not in ("json", "html"):
        return _error(400, "format must be 'json' or 'html'")
    if not limiter.allow(client_ip):
        return _error(429, "too many scans, please wait a minute")

    try:
        target = normalize_target(raw_target)
        assert_public_url(target)
    except BlockedTargetError as exc:
        return _error(403, f"target not allowed: {exc.public_message}")
    except ValueError as exc:
        return _error(400, str(exc))
    except Exception as exc:  # DNS failure etc.
        return _error(422, str(exc))

    client = HttpClient(timeout=WEB_TIMEOUT, url_guard=assert_public_url)
    ctx = ScanContext(target, client=client)
    result = Scanner(client=client).scan(target, context=ctx)
    if "error" in result.metadata:
        if result.metadata.get("blocked"):
            return _error(403, f"target not allowed: {result.metadata['error_public']}")
        return _error(422, f"could not reach {target}: {result.metadata['error_public']}")

    if fmt == "html":
        return WebResponse(200, "text/html; charset=utf-8", render_html(result).encode(), list(REPORT_SECURITY_HEADERS))
    return WebResponse(200, "application/json; charset=utf-8", render_json(result).encode(), list(API_SECURITY_HEADERS))


def static_file(name: str) -> WebResponse:
    content_type = STATIC_FILES.get(name)
    path = STATIC_DIR / name
    if content_type is None or not path.is_file():
        return _error(404, "not found")
    headers = [*PAGE_SECURITY_HEADERS, ("Cache-Control", "public, max-age=300")]
    return WebResponse(200, content_type, path.read_bytes(), headers)


def handle_request(path: str, query: str, client_ip: str) -> WebResponse:
    """Route a GET request. Shared by the Vercel functions and ``safescope serve``."""
    if path == "/api/scan":
        return handle_scan(query, client_ip)
    if path == "/api/health":
        return WebResponse(200, "application/json", b'{"status":"ok"}', list(API_SECURITY_HEADERS))
    if path == "/.well-known/security.txt":
        return WebResponse(200, "text/plain; charset=utf-8", SECURITY_TXT.encode(), list(API_SECURITY_HEADERS))
    if path in ("/", "/index.html"):
        return static_file("index.html")
    name = path.lstrip("/")
    if name in STATIC_FILES:
        return static_file(name)
    return _error(404, "not found")


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the web UI + API locally (``safescope serve``)."""
    import http.server
    from urllib.parse import urlsplit

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "SafeScope"
        sys_version = ""

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            resp = handle_request(parts.path, parts.query, self.client_address[0])
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            for name, value in resp.headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    print(f"SafeScope web UI on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
