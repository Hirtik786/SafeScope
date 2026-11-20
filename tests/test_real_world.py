"""Tests against real public websites.

They are skipped by default (no internet in many dev setups). Run them with:

    pytest -m network --run-network

Most targets are on badssl.com, a site maintained by the Chrome security team
specifically so tools like SafeScope can be tested against known-bad TLS setups.
"""

from __future__ import annotations

import json

import pytest

from safescope import scan
from safescope.web import RateLimiter, handle_scan

pytestmark = pytest.mark.network


def ids(result):
    return {f.id for f in result.findings}


@pytest.mark.parametrize(
    "target",
    [
        "https://expired.badssl.com/",
        "https://self-signed.badssl.com/",
        "https://wrong.host.badssl.com/",
        "https://untrusted-root.badssl.com/",
    ],
)
def test_bad_certificates_are_flagged(target):
    result = scan(target)
    assert "tls.certificate.untrusted" in ids(result), result.to_dict()
    # an untrusted certificate must not abort the rest of the scan
    assert any(f.check_id == "headers" and f.status.value != "error" for f in result.findings)
    assert result.grade in ("C", "D", "F")


def test_legacy_only_tls_server():
    result = scan("https://tls-v1-0.badssl.com:1010/")
    found = ids(result)
    # Depending on the local OpenSSL build the probe may be impossible; it must never claim "modern".
    assert "tls.protocol.modern" not in found
    assert found & {"tls.protocol.legacy_only", "tls.handshake"}


def test_valid_certificate_and_hsts():
    result = scan("https://hsts.badssl.com/")
    found = ids(result)
    assert "tls.certificate.valid" in found
    assert "tls.protocol.modern" in found
    assert "transport.hsts.present" in found or "transport.hsts.subdomains" in found


@pytest.mark.parametrize("target", ["github.com", "www.google.com", "www.cloudflare.com", "en.wikipedia.org"])
def test_major_sites_scan_cleanly(target):
    """Big, well-run sites: the scan must complete without crashes or errors."""
    result = scan(target)
    errors = [f for f in result.findings if f.status.value == "error"]
    assert not errors, [(f.id, f.description) for f in errors]
    assert "tls.certificate.valid" in ids(result)
    assert "transport.https.available" in ids(result)
    assert result.final_url.startswith("https://")


def test_web_api_on_a_real_site():
    resp = handle_scan("target=github.com", "203.0.113.7", limiter=RateLimiter())
    assert resp.status == 200, resp.body
    data = json.loads(resp.body)
    assert data["grade"] and data["findings"]


def test_web_api_blocks_internal_hostnames_that_resolve_privately():
    # localtest.me is a public DNS name that resolves to 127.0.0.1 - a classic SSRF trick.
    resp = handle_scan("target=localtest.me", "203.0.113.7", limiter=RateLimiter())
    assert resp.status in (403, 422)
