"""HTTP security response headers."""

from __future__ import annotations

from safescope.checks.base import Check
from safescope.context import ScanContext
from safescope.http import FetchError, Headers
from safescope.models import Finding, Severity, Status

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"

GOOD_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy into ``{directive: [sources...]}``."""
    policy: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        tokens = chunk.strip().split()
        if tokens:
            policy.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return policy


class HeadersCheck(Check):
    id = "headers"
    name = "Security headers"
    description = "Looks for browser security headers such as CSP, X-Frame-Options and Referrer-Policy."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.main_response()
        except FetchError as exc:
            return [self.error("fetch", "Could not fetch the page", str(exc))]
        return self.analyze(resp.headers)

    def analyze(self, headers: Headers) -> list[Finding]:
        """Pure function: headers in, findings out (easy to unit-test)."""
        findings: list[Finding] = []
        csp_value = headers.get("Content-Security-Policy")
        csp = parse_csp(csp_value) if csp_value else {}

        findings.extend(self._csp(csp_value, csp))
        findings.append(self._framing(headers.get("X-Frame-Options"), csp))
        findings.append(self._nosniff(headers.get("X-Content-Type-Options")))
        findings.append(self._referrer(headers.get("Referrer-Policy")))
        findings.append(self._permissions(headers.get("Permissions-Policy")))
        xss = headers.get("X-XSS-Protection")
        if xss and xss.strip().startswith("1"):
            findings.append(
                self.finding(
                    "x_xss_protection.enabled",
                    "Deprecated X-XSS-Protection filter is enabled",
                    Status.WARN,
                    Severity.LOW,
                    description="The legacy XSS auditor has been removed from modern browsers and "
                    "could introduce cross-site leaks in old ones.",
                    recommendation="Send 'X-XSS-Protection: 0' (or drop it) and rely on a strong CSP.",
                    evidence=xss,
                    references=[MDN + "X-XSS-Protection"],
                )
            )
        return findings

    def _csp(self, raw: str | None, csp: dict[str, list[str]]) -> list[Finding]:
        ref = [MDN + "Content-Security-Policy"]
        if not raw:
            return [
                self.finding(
                    "csp.missing",
                    "Content-Security-Policy header is missing",
                    Status.FAIL,
                    Severity.MEDIUM,
                    description="A CSP is the strongest browser-side defence against cross-site "
                    "scripting (XSS) and data injection.",
                    recommendation="Start with \"Content-Security-Policy: default-src 'self'\" and "
                    "loosen it only where needed. Try it first with "
                    "Content-Security-Policy-Report-Only.",
                    references=ref,
                )
            ]
        out: list[Finding] = []
        script_src = csp.get("script-src", csp.get("default-src", []))
        weak = [s for s in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:") if s in script_src]
        # 'unsafe-inline' is ignored by browsers when a nonce or hash is present.
        if "'unsafe-inline'" in weak and any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_src
        ):
            weak.remove("'unsafe-inline'")
        if weak:
            out.append(
                self.finding(
                    "csp.unsafe",
                    "CSP allows unsafe script sources",
                    Status.WARN,
                    Severity.MEDIUM,
                    description="These sources weaken the policy enough that it may not stop XSS: " + ", ".join(weak),
                    recommendation="Replace inline scripts with nonces or hashes and remove "
                    "'unsafe-eval' and wildcards from script-src.",
                    evidence=raw,
                    references=ref,
                )
            )
        else:
            out.append(self.passed("csp.present", "Content-Security-Policy is set", raw))
        return out

    def _framing(self, xfo: str | None, csp: dict[str, list[str]]) -> Finding:
        if "frame-ancestors" in csp:
            return self.passed(
                "framing.protected",
                "Clickjacking protection via CSP frame-ancestors",
                "frame-ancestors " + " ".join(csp["frame-ancestors"]),
            )
        if xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
            return self.passed("framing.protected", "Clickjacking protection via X-Frame-Options", xfo)
        return self.finding(
            "framing.missing",
            "No clickjacking protection",
            Status.FAIL,
            Severity.MEDIUM,
            description="Other sites can embed this page in an invisible frame and trick users into "
            "clicking on it (clickjacking).",
            recommendation="Send \"Content-Security-Policy: frame-ancestors 'self'\" or 'X-Frame-Options: DENY'.",
            evidence=xfo or "",
            references=[MDN + "X-Frame-Options", MDN + "Content-Security-Policy/frame-ancestors"],
        )

    def _nosniff(self, value: str | None) -> Finding:
        if value and value.strip().lower() == "nosniff":
            return self.passed("nosniff.present", "X-Content-Type-Options is nosniff", value)
        return self.finding(
            "nosniff.missing",
            "X-Content-Type-Options: nosniff is missing",
            Status.FAIL,
            Severity.LOW,
            description="Browsers may guess ('sniff') content types and execute uploaded files as scripts.",
            recommendation="Send 'X-Content-Type-Options: nosniff'.",
            evidence=value or "",
            references=[MDN + "X-Content-Type-Options"],
        )

    def _referrer(self, value: str | None) -> Finding:
        policies = [p.strip().lower() for p in (value or "").split(",") if p.strip()]
        effective = policies[-1] if policies else ""
        if effective in GOOD_REFERRER_POLICIES:
            return self.passed("referrer.present", "Referrer-Policy limits leaked URLs", value or "")
        return self.finding(
            "referrer.weak" if value else "referrer.missing",
            "Referrer-Policy is weak" if value else "Referrer-Policy header is missing",
            Status.WARN,
            Severity.LOW,
            description="Full URLs (which may contain tokens or private paths) can leak to other "
            "sites through the Referer header.",
            recommendation="Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
            evidence=value or "",
            references=[MDN + "Referrer-Policy"],
        )

    def _permissions(self, value: str | None) -> Finding:
        if value:
            return self.passed("permissions.present", "Permissions-Policy is set", value)
        return self.finding(
            "permissions.missing",
            "Permissions-Policy header is missing",
            Status.WARN,
            Severity.LOW,
            description="Without it, embedded content may request powerful features such as the "
            "camera, microphone or geolocation.",
            recommendation="Disable what you do not use, e.g. "
            "'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            references=[MDN + "Permissions-Policy", OWASP_HEADERS],
        )
