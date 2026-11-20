from __future__ import annotations

import pytest
from conftest import GOOD_HEADERS

from safescope.checks.headers import HeadersCheck, parse_csp
from safescope.http import Headers
from safescope.models import Severity, Status


def analyze(headers: dict[str, str]):
    findings = HeadersCheck().analyze(Headers.from_pairs(headers.items()))
    return {f.id: f for f in findings}


def test_parse_csp_lowercases_and_keeps_first_directive():
    policy = parse_csp("Default-Src 'self'; script-src 'self' CDN.example; script-src 'none'")
    assert policy == {"default-src": ["'self'"], "script-src": ["'self'", "cdn.example"]}


def test_all_good_headers_pass():
    results = analyze(GOOD_HEADERS)
    assert all(f.status is Status.PASS for f in results.values()), results


def test_missing_everything():
    results = analyze({})
    assert results["headers.csp.missing"].severity is Severity.MEDIUM
    assert results["headers.framing.missing"].status is Status.FAIL
    assert results["headers.nosniff.missing"].status is Status.FAIL
    assert results["headers.referrer.missing"].status is Status.WARN
    assert results["headers.permissions.missing"].status is Status.WARN


@pytest.mark.parametrize(
    "csp, expect_unsafe",
    [
        ("script-src 'self' 'unsafe-inline'", True),
        ("default-src *", True),
        ("script-src 'self' 'unsafe-eval'", True),
        ("script-src 'nonce-abc' 'unsafe-inline'", False),  # nonce neutralises unsafe-inline
        ("default-src 'self'", False),
    ],
)
def test_csp_unsafe_sources(csp, expect_unsafe):
    results = analyze({"Content-Security-Policy": csp})
    assert ("headers.csp.unsafe" in results) is expect_unsafe


def test_x_frame_options_counts_as_framing_protection():
    results = analyze({"X-Frame-Options": "sameorigin"})
    assert results["headers.framing.protected"].status is Status.PASS


def test_invalid_x_frame_options_is_not_protection():
    results = analyze({"X-Frame-Options": "ALLOW-FROM https://x"})
    assert "headers.framing.missing" in results


def test_referrer_policy_uses_last_value_of_list():
    assert "headers.referrer.present" in analyze({"Referrer-Policy": "unsafe-url, no-referrer"})
    assert "headers.referrer.weak" in analyze({"Referrer-Policy": "no-referrer, unsafe-url"})


def test_x_xss_protection_enabled_is_flagged_but_zero_is_fine():
    assert "headers.x_xss_protection.enabled" in analyze({"X-XSS-Protection": "1; mode=block"})
    assert "headers.x_xss_protection.enabled" not in analyze({"X-XSS-Protection": "0"})


def test_header_lookup_is_case_insensitive():
    results = analyze({"x-content-type-options": "NoSniff"})
    assert results["headers.nosniff.present"].status is Status.PASS
