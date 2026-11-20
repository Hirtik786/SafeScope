from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from safescope.checks.tls_check import TLSCheck
from safescope.models import Severity, Status
from safescope.tls import TLSInfo


def info(**kw) -> TLSInfo:
    base = dict(
        host="example.com",
        port=443,
        connected=True,
        verified=True,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        subject_cn="example.com",
        issuer="Let's Encrypt",
        not_after=datetime.now(timezone.utc) + timedelta(days=90),
    )
    base.update(kw)
    return TLSInfo(**base)


def analyze(i: TLSInfo):
    return {f.id: f for f in TLSCheck().analyze(i)}


def test_healthy_tls():
    f = analyze(info())
    assert all(x.status is Status.PASS for x in f.values())
    assert "tls.protocol.no_legacy" in f


@pytest.mark.parametrize(
    "days, fid, severity",
    [
        (-2, "tls.certificate.expired", Severity.CRITICAL),
        (3, "tls.certificate.expiring", Severity.HIGH),
        (20, "tls.certificate.expiring", Severity.LOW),
    ],
)
def test_expiry(days, fid, severity):
    f = analyze(info(not_after=datetime.now(timezone.utc) + timedelta(days=days, hours=1)))
    assert f[fid].severity is severity


def test_untrusted_certificate():
    f = analyze(info(verified=False, verify_error="self-signed certificate", not_after=None))
    assert f["tls.certificate.untrusted"].severity is Severity.HIGH
    assert f["tls.certificate.untrusted"].evidence == "self-signed certificate"


def test_legacy_protocols():
    f = analyze(info(legacy_protocols=["TLSv1.0"]))
    assert f["tls.protocol.legacy"].status is Status.WARN
    f = analyze(info(legacy_probe_possible=False))
    assert f["tls.protocol.legacy_untested"].status is Status.INFO


def test_outdated_negotiated_protocol():
    assert "tls.protocol.outdated" in analyze(info(protocol="TLSv1"))


def test_handshake_failure_is_informational():
    f = analyze(TLSInfo(host="x", port=443, error="refused"))
    assert f["tls.handshake"].status is Status.INFO


def test_server_that_only_speaks_legacy_tls():
    f = analyze(TLSInfo(host="x", port=443, error="unsupported protocol", legacy_protocols=["TLSv1.0"]))
    assert f["tls.protocol.legacy_only"].severity is Severity.HIGH
