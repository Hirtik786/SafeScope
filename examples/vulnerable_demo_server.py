"""A deliberately misconfigured local web server for trying SafeScope safely.

    python examples/vulnerable_demo_server.py          # serves http://127.0.0.1:8000
    safescope scan http://127.0.0.1:8000 -f html -o demo-report.html

It only listens on localhost, so you are scanning your own machine - no
permission issues. Pass --fixed to see what a well configured response looks like.
"""

from __future__ import annotations

import argparse
import http.server

BAD_HEADERS = [
    ("Server", "Apache/2.4.41 (Ubuntu)"),
    ("X-Powered-By", "PHP/7.4.3"),
    ("X-XSS-Protection", "1; mode=block"),
    ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'"),
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Credentials", "true"),
    ("Set-Cookie", "PHPSESSID=demo123; Path=/"),
    ("Set-Cookie", "tracking=1; SameSite=None"),
]

GOOD_HEADERS = [
    ("Server", "demo"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Set-Cookie", "sessionid=demo123; Path=/; HttpOnly; SameSite=Lax"),
]

SECURITY_TXT = b"Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"


def make_handler(fixed: bool) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "demo"
        sys_version = ""

        def do_GET(self) -> None:
            if self.path == "/.well-known/security.txt" and fixed:
                self._send(200, [("Content-Type", "text/plain")], SECURITY_TXT)
                return
            if self.path != "/":
                self._send(404, [("Content-Type", "text/plain")], b"not found")
                return
            headers = GOOD_HEADERS if fixed else BAD_HEADERS
            body = b"<!doctype html><title>SafeScope demo</title><h1>SafeScope demo target</h1>"
            self._send(200, [("Content-Type", "text/html; charset=utf-8"), *headers], body)

        def _send(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--fixed", action="store_true", help="serve secure headers instead")
    args = parser.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args.fixed))
    mode = "secure" if args.fixed else "INSECURE"
    print(f"Serving {mode} demo on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
