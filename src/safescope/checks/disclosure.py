"""Information disclosure, security.txt and CORS configuration."""

from __future__ import annotations

import re

from safescope.checks.base import Check
from safescope.context import ScanContext
from safescope.http import FetchError, Headers
from safescope.models import Finding, Severity, Status

VERSION_RE = re.compile(r"\d+\.\d+")
SECURITY_TXT = "https://securitytxt.org/"
OWASP_FINGERPRINT = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
    "01-Information_Gathering/02-Fingerprint_Web_Server"
)


class DisclosureCheck(Check):
    id = "disclosure"
    name = "Information disclosure"
    description = "Spots software versions leaked in headers, checks CORS and looks for a security.txt contact."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.main_response()
        except FetchError as exc:
            return [self.error("fetch", "Could not fetch the page", str(exc))]

        findings = self.analyze_headers(resp.headers)
        findings.append(self._security_txt(ctx))
        return findings

    def analyze_headers(self, headers: Headers) -> list[Finding]:
        out: list[Finding] = []
        leaks = []
        for server in headers.get_all("Server"):
            if VERSION_RE.search(server):
                leaks.append(f"Server: {server}")
        for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
            value = headers.get(name)
            if value:
                leaks.append(f"{name}: {value}")
        if leaks:
            out.append(
                self.finding(
                    "versions",
                    "Software versions are disclosed in headers",
                    Status.WARN,
                    Severity.LOW,
                    description="Version banners make it easier to match the server against known vulnerabilities.",
                    recommendation="Hide version numbers (e.g. 'server_tokens off;' in nginx, "
                    "'ServerTokens Prod' in Apache, remove X-Powered-By).",
                    evidence="; ".join(leaks),
                    references=[OWASP_FINGERPRINT],
                )
            )
        else:
            out.append(self.passed("versions", "No software versions in response headers"))

        acao = headers.get("Access-Control-Allow-Origin")
        acac = (headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        if acao and acao.strip() == "*" and acac:
            out.append(
                self.finding(
                    "cors.wildcard_credentials",
                    "CORS allows any origin together with credentials",
                    Status.FAIL,
                    Severity.MEDIUM,
                    description="This combination is invalid and signals a CORS configuration that "
                    "may reflect arbitrary origins on other endpoints.",
                    recommendation="Allow-list specific trusted origins instead of '*'.",
                    evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
                )
            )
        elif acao and acao.strip() == "*":
            out.append(
                self.finding(
                    "cors.wildcard",
                    "CORS is open to every origin",
                    Status.INFO,
                    description="Fine for public, read-only content; make sure no private data is "
                    "served with this header.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                )
            )
        return out

    def _security_txt(self, ctx: ScanContext) -> Finding:
        try:
            resp = ctx.fetch_path("/.well-known/security.txt")
        except FetchError as exc:
            return self.error("security_txt", "Could not request security.txt", str(exc))
        content_type = (resp.headers.get("Content-Type") or "").lower()
        if resp.status == 200 and "contact:" in resp.text.lower() and "html" not in content_type:
            contact = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in resp.text.splitlines()
                    if line.lower().startswith("contact:")
                ),
                "",
            )
            return self.passed("security_txt", "security.txt publishes a security contact", contact)
        return self.finding(
            "security_txt.missing",
            "No security.txt file",
            Status.WARN,
            Severity.INFO,
            description="security.txt (RFC 9116) tells researchers how to report vulnerabilities to you responsibly.",
            recommendation="Publish /.well-known/security.txt with at least 'Contact:' and 'Expires:'.",
            evidence=f"HTTP {resp.status}",
            references=[SECURITY_TXT],
        )
