"""HTTPS availability, HTTP -> HTTPS redirection and HSTS."""

from __future__ import annotations

import re

from safescope.checks.base import Check
from safescope.context import ScanContext
from safescope.http import FetchError, Response
from safescope.models import Finding, Severity, Status

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days, the commonly recommended minimum
MDN_HSTS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
OWASP_TLS = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"


def parse_hsts(value: str) -> dict[str, str | bool]:
    """Parse an HSTS header into ``{"max-age": "31536000", "includesubdomains": True}``."""
    directives: dict[str, str | bool] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, val = part.partition("=")
            directives[key.strip().lower()] = val.strip().strip('"')
        else:
            directives[part.lower()] = True
    return directives


class TransportCheck(Check):
    id = "transport"
    name = "HTTPS & HSTS"
    description = "Verifies the site is served over HTTPS, redirects plain HTTP and sends a solid HSTS policy."

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Is HTTPS reachable at all?
        https_resp: Response | None
        try:
            https_resp = ctx.fetch(ctx.https_url())
        except FetchError as exc:
            findings.append(
                self.finding(
                    "https.unavailable",
                    "HTTPS is not available",
                    Status.FAIL,
                    Severity.HIGH,
                    description="The site could not be loaded over HTTPS, so all traffic can be read "
                    "or modified by anyone on the network path.",
                    recommendation="Serve the site over HTTPS (free certificates are available from "
                    "Let's Encrypt).",
                    evidence=str(exc),
                    references=[OWASP_TLS],
                )
            )
            https_resp = None
        if https_resp is not None:
            if https_resp.scheme == "https":
                findings.append(self.passed("https.available", "Site is reachable over HTTPS", https_resp.url))
            else:
                findings.append(
                    self.finding(
                        "https.downgrade",
                        "HTTPS redirects back to plain HTTP",
                        Status.FAIL,
                        Severity.HIGH,
                        description="Requesting the HTTPS URL ends on an http:// page.",
                        recommendation="Remove the redirect to HTTP and serve all content over HTTPS.",
                        evidence=" -> ".join([u for _, u in https_resp.redirect_chain] + [https_resp.url]),
                    )
                )

        # 2. Does plain HTTP upgrade to HTTPS?
        try:
            http_resp = ctx.fetch(ctx.http_url())
        except FetchError:
            findings.append(
                self.finding(
                    "http.closed",
                    "Plain HTTP is not served",
                    Status.INFO,
                    description="Port 80 did not answer. That is safe, although many sites keep it "
                    "open only to redirect visitors to HTTPS.",
                )
            )
        else:
            if http_resp.scheme == "https":
                first_status = http_resp.redirect_chain[0][0] if http_resp.redirect_chain else 0
                findings.append(
                    self.passed(
                        "http.redirects",
                        "HTTP redirects to HTTPS",
                        f"{first_status} {ctx.http_url()} -> {http_resp.url}",
                    )
                )
            else:
                findings.append(
                    self.finding(
                        "http.no_redirect",
                        "HTTP does not redirect to HTTPS",
                        Status.FAIL,
                        Severity.MEDIUM,
                        description="Visitors who type the address without https:// stay on an "
                        "unencrypted connection.",
                        recommendation="Answer every plain HTTP request with a 301 redirect to the "
                        "HTTPS version of the same URL.",
                        evidence=f"{ctx.http_url()} answered {http_resp.status} without redirecting",
                        references=[OWASP_TLS],
                    )
                )

        # 3. HSTS (only meaningful over HTTPS)
        if https_resp is not None and https_resp.scheme == "https":
            findings.extend(self._check_hsts(https_resp.headers.get("Strict-Transport-Security")))
        return findings

    def _check_hsts(self, value: str | None) -> list[Finding]:
        if not value:
            return [
                self.finding(
                    "hsts.missing",
                    "Strict-Transport-Security header is missing",
                    Status.FAIL,
                    Severity.MEDIUM,
                    description="Without HSTS a network attacker can strip HTTPS on a visitor's "
                    "first request (SSL stripping).",
                    recommendation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                    references=[MDN_HSTS],
                )
            ]
        directives = parse_hsts(value)
        raw_age = directives.get("max-age")
        age = int(raw_age) if isinstance(raw_age, str) and re.fullmatch(r"\d+", raw_age) else None
        if age is None:
            return [
                self.finding(
                    "hsts.invalid",
                    "HSTS header has no valid max-age",
                    Status.FAIL,
                    Severity.MEDIUM,
                    recommendation="Use a numeric max-age, e.g. 'max-age=31536000'.",
                    evidence=value,
                    references=[MDN_HSTS],
                )
            ]
        if age < HSTS_MIN_MAX_AGE:
            return [
                self.finding(
                    "hsts.short",
                    "HSTS max-age is shorter than 180 days",
                    Status.WARN,
                    Severity.LOW,
                    description="A short max-age means browsers forget the policy quickly.",
                    recommendation="Raise max-age to at least 15552000 (180 days); 31536000 is common.",
                    evidence=value,
                    references=[MDN_HSTS],
                )
            ]
        out = [self.passed("hsts.present", "HSTS is enabled with a long max-age", value)]
        if "includesubdomains" not in directives:
            out.append(
                self.finding(
                    "hsts.subdomains",
                    "HSTS does not cover subdomains",
                    Status.WARN,
                    Severity.LOW,
                    description="Subdomains can still be reached over plain HTTP.",
                    recommendation="Add 'includeSubDomains' once every subdomain supports HTTPS.",
                    evidence=value,
                    references=[MDN_HSTS],
                )
            )
        return out
