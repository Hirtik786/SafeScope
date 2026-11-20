"""Certificate validity, expiry and protocol versions."""

from __future__ import annotations

from safescope.checks.base import Check
from safescope.context import ScanContext
from safescope.models import Finding, Severity, Status
from safescope.tls import TLSInfo

EXPIRY_WARN_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7
MOZILLA_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS"
RFC_8996 = "https://datatracker.ietf.org/doc/html/rfc8996"


class TLSCheck(Check):
    id = "tls"
    name = "TLS & certificate"
    description = "Checks the certificate chain, expiry date and which TLS versions the server accepts."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            info = ctx.tls_info()
        except Exception as exc:  # inspector is pluggable; never let it kill the scan
            return [self.error("inspect", "TLS inspection failed", str(exc))]
        return self.analyze(info)

    def analyze(self, info: TLSInfo) -> list[Finding]:
        if not info.connected and info.legacy_protocols:
            return [
                self.finding(
                    "protocol.legacy_only",
                    "Server only supports deprecated TLS versions",
                    Status.FAIL,
                    Severity.HIGH,
                    description="Modern clients refuse to connect: the server negotiates only "
                    + ", ".join(info.legacy_protocols)
                    + ", which were deprecated in 2021 (RFC 8996).",
                    recommendation="Enable TLS 1.2 and TLS 1.3 and disable TLS 1.0/1.1.",
                    evidence=info.error,
                    references=[RFC_8996, MOZILLA_TLS],
                )
            ]
        if not info.connected:
            return [
                self.finding(
                    "handshake",
                    "TLS handshake failed",
                    Status.INFO,
                    description="Could not open a TLS connection; see the HTTPS check for impact.",
                    evidence=info.error,
                )
            ]

        out: list[Finding] = []
        if info.verified:
            out.append(
                self.passed(
                    "certificate.valid",
                    "Certificate is trusted and matches the host name",
                    f"CN={info.subject_cn} issued by {info.issuer}".strip(),
                )
            )
        else:
            out.append(
                self.finding(
                    "certificate.untrusted",
                    "Certificate is not trusted",
                    Status.FAIL,
                    Severity.HIGH,
                    description="Browsers will show a full-page warning. Typical causes: self-signed "
                    "certificate, expired certificate, missing intermediate or wrong host name.",
                    recommendation="Install a certificate from a public CA that covers this host "
                    "name and serve the full chain.",
                    evidence=info.verify_error,
                    references=[MOZILLA_TLS],
                )
            )

        days = info.days_left
        if days is not None:
            if days < 0:
                out.append(
                    self.finding("certificate.expired", "Certificate has expired", Status.FAIL,
                                 Severity.CRITICAL, evidence=f"expired {-days} day(s) ago",
                                 recommendation="Renew the certificate immediately.")
                )
            elif days <= EXPIRY_CRITICAL_DAYS:
                out.append(
                    self.finding("certificate.expiring", f"Certificate expires in {days} day(s)",
                                 Status.FAIL, Severity.HIGH,
                                 recommendation="Renew now and automate renewal (e.g. certbot).",
                                 evidence=f"notAfter={info.not_after:%Y-%m-%d}")
                )
            elif days <= EXPIRY_WARN_DAYS:
                out.append(
                    self.finding("certificate.expiring", f"Certificate expires in {days} day(s)",
                                 Status.WARN, Severity.LOW,
                                 recommendation="Make sure automatic renewal is working.",
                                 evidence=f"notAfter={info.not_after:%Y-%m-%d}")
                )
            else:
                out.append(self.passed("certificate.expiry", f"Certificate valid for {days} more days",
                                       f"notAfter={info.not_after:%Y-%m-%d}"))

        if info.protocol in ("TLSv1.3", "TLSv1.2"):
            out.append(self.passed("protocol.modern", f"Negotiated {info.protocol}",
                                   f"{info.cipher} ({info.cipher_bits} bits)"))
        elif info.protocol:
            out.append(
                self.finding("protocol.outdated", f"Server negotiated outdated {info.protocol}",
                             Status.FAIL, Severity.HIGH,
                             recommendation="Enable TLS 1.2 and TLS 1.3.", references=[RFC_8996])
            )

        if info.legacy_protocols:
            out.append(
                self.finding(
                    "protocol.legacy",
                    "Deprecated TLS versions are still accepted",
                    Status.WARN,
                    Severity.MEDIUM,
                    description="TLS 1.0 and 1.1 were formally deprecated in 2021 (RFC 8996).",
                    recommendation="Disable TLS 1.0 and 1.1 on the server.",
                    evidence=", ".join(info.legacy_protocols),
                    references=[RFC_8996, MOZILLA_TLS],
                )
            )
        elif info.legacy_probe_possible:
            out.append(self.passed("protocol.no_legacy", "TLS 1.0 and 1.1 are disabled"))
        else:
            out.append(
                self.finding("protocol.legacy_untested", "Legacy TLS versions not tested",
                             Status.INFO,
                             description="The local OpenSSL build cannot offer TLS 1.0/1.1, so "
                             "support for them could not be checked.")
            )
        return out
