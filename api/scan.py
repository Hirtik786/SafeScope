"""Vercel serverless entry point.

``vercel.json`` rewrites every path to this function and passes the original
path in the ``path`` query parameter, so all routing lives in
:func:`safescope.web.handle_request` (the same code ``safescope serve`` uses).
"""

from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safescope.web import handle_request  # noqa: E402


class handler(BaseHTTPRequestHandler):  # noqa: N801  (name required by Vercel)
    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        params = parse_qsl(parts.query, keep_blank_values=True)
        route = next((v for k, v in params if k == "path"), None)
        path = "/" + route.lstrip("/") if route is not None else parts.path
        query = urlencode([(k, v) for k, v in params if k != "path"])

        forwarded = self.headers.get("x-real-ip") or self.headers.get("x-forwarded-for") or ""
        client_ip = forwarded.split(",")[0].strip() or self.client_address[0]

        resp = handle_request(path, query, client_ip)
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.content_type)
        for name, value in resp.headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(resp.body)
