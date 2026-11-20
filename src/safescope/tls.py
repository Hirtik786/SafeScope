"""TLS inspection using only the standard library ``ssl`` module."""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TLSInfo:
    host: str
    port: int
    connected: bool = False
    error: str = ""
    verified: bool = False
    verify_error: str = ""
    protocol: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    subject_cn: str = ""
    issuer: str = ""
    not_after: datetime | None = None
    san: list[str] = field(default_factory=list)
    legacy_protocols: list[str] = field(default_factory=list)
    """Deprecated protocol versions (TLS 1.0/1.1) the server still accepted."""
    legacy_probe_possible: bool = True
    """False when the local OpenSSL build cannot even offer the old versions."""

    @property
    def days_left(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(timezone.utc)).days


SERVER_REJECTION_MARKERS = ("ALERT_PROTOCOL_VERSION", "ALERT_HANDSHAKE_FAILURE", "WRONG_SSL_VERSION")


def _name_field(name: Any, key: str) -> str:
    for rdn in name:
        for k, v in rdn:
            if k == key:
                return str(v)
    return ""


def _handshake(
    host: str, port: int, timeout: float, ctx: ssl.SSLContext, connect_ip: str | None = None
) -> ssl.SSLSocket:
    # connect_ip pins the TCP connection to an address validated by the SSRF
    # guard; server_hostname keeps SNI and certificate checks on the real name.
    raw = socket.create_connection((connect_ip or host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def _probe_legacy(host: str, port: int, timeout: float, info: TLSInfo, connect_ip: str | None = None) -> None:
    candidates = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]
    for label, version in candidates:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            # Probing deprecated versions is the whole point here, so silence the warning.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = version
                ctx.maximum_version = version
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            info.legacy_probe_possible = False
            continue
        try:
            with _handshake(host, port, timeout, ctx, connect_ip):
                info.legacy_protocols.append(label)
        except ssl.SSLError as exc:
            # Only a server alert proves the server refused the version. Anything else
            # (e.g. "no protocols available" from our own OpenSSL) means "not tested".
            message = str(exc).upper()
            if not any(marker in message for marker in SERVER_REJECTION_MARKERS):
                info.legacy_probe_possible = False
        except OSError:
            info.legacy_probe_possible = False


def inspect_tls(host: str, port: int = 443, timeout: float = 10.0, connect_ip: str | None = None) -> TLSInfo:
    info = TLSInfo(host=host, port=port)
    ctx = ssl.create_default_context()
    try:
        sock = _handshake(host, port, timeout, ctx, connect_ip)
        info.verified = True
    except ssl.SSLCertVerificationError as exc:
        info.verify_error = exc.verify_message or str(exc)
        unverified = ssl.create_default_context()
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        try:
            sock = _handshake(host, port, timeout, unverified, connect_ip)
        except (OSError, ssl.SSLError) as exc2:
            info.error = str(exc2)
            return info
    except ssl.SSLError as exc:
        info.error = str(exc) or exc.__class__.__name__
        # A modern handshake failed: maybe the server *only* speaks deprecated TLS.
        _probe_legacy(host, port, timeout, info, connect_ip)
        return info
    except OSError as exc:
        info.error = str(exc) or exc.__class__.__name__
        return info

    with sock:
        info.connected = True
        info.protocol = sock.version() or ""
        cipher = sock.cipher()
        if cipher:
            info.cipher, _, bits = cipher
            info.cipher_bits = bits or 0
        cert = sock.getpeercert()  # empty dict when unverified
        if cert:
            info.subject_cn = _name_field(cert.get("subject", ()), "commonName")
            info.issuer = _name_field(cert.get("issuer", ()), "organizationName") or _name_field(
                cert.get("issuer", ()), "commonName"
            )
            not_after = cert.get("notAfter")
            if isinstance(not_after, str):
                ts = ssl.cert_time_to_seconds(not_after)
                info.not_after = datetime.fromtimestamp(ts, tz=timezone.utc)
            san: Any = cert.get("subjectAltName", ())
            info.san = [str(v) for k, v in san if k == "DNS"]

    _probe_legacy(host, port, timeout, info, connect_ip)
    return info
