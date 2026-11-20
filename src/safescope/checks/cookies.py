"""Cookie security attributes (Secure, HttpOnly, SameSite)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from safescope.checks.base import Check
from safescope.context import ScanContext
from safescope.http import FetchError, Response
from safescope.models import Finding, Severity, Status

SENSITIVE_NAME = re.compile(r"sess|sid|auth|token|jwt|login|csrf|xsrf|remember", re.IGNORECASE)
MDN_COOKIES = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"


@dataclass
class Cookie:
    name: str
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def http_only(self) -> bool:
        return "httponly" in self.attributes

    @property
    def same_site(self) -> str:
        return self.attributes.get("samesite", "").lower()

    @property
    def looks_sensitive(self) -> bool:
        return bool(SENSITIVE_NAME.search(self.name))


def parse_set_cookie(header: str) -> Cookie:
    """Parse one Set-Cookie header value (we never keep the cookie's value)."""
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return Cookie(name=name, attributes=attrs)


class CookiesCheck(Check):
    id = "cookies"
    name = "Cookie security"
    description = "Ensures cookies set by the page use the Secure, HttpOnly and SameSite attributes."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.main_response()
        except FetchError as exc:
            return [self.error("fetch", "Could not fetch the page", str(exc))]
        return self.analyze(resp)

    def analyze(self, resp: Response) -> list[Finding]:
        cookies = [parse_set_cookie(v) for v in resp.headers.get_all("Set-Cookie")]
        if not cookies:
            return [self.finding("none", "No cookies set on the landing page", Status.INFO)]

        is_https = resp.scheme == "https"
        out: list[Finding] = []
        for c in cookies:
            problems: list[tuple[str, str, Severity]] = []
            if is_https and not c.secure:
                sev = Severity.MEDIUM if c.looks_sensitive else Severity.LOW
                problems.append(("secure", "missing Secure", sev))
            if c.looks_sensitive and not c.http_only:
                problems.append(("httponly", "missing HttpOnly", Severity.MEDIUM))
            if not c.same_site:
                problems.append(("samesite", "missing SameSite", Severity.LOW))
            elif c.same_site == "none" and not c.secure:
                problems.append(("samesite", "SameSite=None without Secure", Severity.MEDIUM))

            if not problems:
                out.append(self.passed(f"{c.name}.ok", f"Cookie '{c.name}' is well configured"))
                continue
            worst = max(p[2] for p in problems)
            out.append(
                self.finding(
                    f"{c.name}.flags",
                    f"Cookie '{c.name}': " + ", ".join(p[1] for p in problems),
                    Status.FAIL if worst >= Severity.MEDIUM else Status.WARN,
                    worst,
                    description=(
                        "Secure keeps the cookie off plain HTTP, HttpOnly hides it from JavaScript "
                        "(limiting XSS damage) and SameSite helps against CSRF."
                    ),
                    recommendation=f"Set-Cookie: {c.name}=...; Secure; HttpOnly; SameSite=Lax",
                    evidence="attributes: " + (", ".join(sorted(c.attributes)) or "(none)"),
                    references=[MDN_COOKIES],
                )
            )
        return out
