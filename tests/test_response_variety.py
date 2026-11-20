"""Checks against unusual but real-world responses (false positives / negatives)."""

from __future__ import annotations

from conftest import GOOD_HEADERS, make_response

from safescope.checks.cookies import CookiesCheck
from safescope.checks.disclosure import DisclosureCheck
from safescope.checks.headers import HeadersCheck
from safescope.checks.transport import TransportCheck
from safescope.http import Headers
from safescope.models import Status


def ids(findings):
    return {f.id: f for f in findings}


def test_error_pages_are_still_judged_on_their_headers(make_ctx):
    """A 500 page with good headers is fine; the status code is not a finding."""
    url = "https://example.com/"
    ctx = make_ctx("example.com", {url: make_response(url, status=500, headers=GOOD_HEADERS)})
    results = ids(HeadersCheck().run(ctx))
    assert all(f.status is Status.PASS for f in results.values())


def test_duplicate_hsts_headers_use_the_first_one_like_browsers(make_ctx):
    url = "https://example.com/"
    resp = make_response(
        url,
        headers=[
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Strict-Transport-Security", "max-age=0"),
        ],
    )
    results = ids(TransportCheck().run(make_ctx("example.com", {url: resp})))
    assert "transport.hsts.present" in results


def test_empty_header_values_count_as_missing():
    results = ids(
        HeadersCheck().analyze(Headers.from_pairs([("Content-Security-Policy", ""), ("X-Frame-Options", "")]))
    )
    assert "headers.csp.missing" in results
    assert "headers.framing.missing" in results


def test_header_values_are_case_and_space_tolerant():
    results = ids(
        HeadersCheck().analyze(
            Headers.from_pairs(
                [
                    ("x-frame-options", "  deny "),
                    ("X-CONTENT-TYPE-OPTIONS", "NOSNIFF"),
                    ("referrer-policy", "No-Referrer"),
                ]
            )
        )
    )
    assert results["headers.framing.protected"].status is Status.PASS
    assert results["headers.nosniff.present"].status is Status.PASS
    assert results["headers.referrer.present"].status is Status.PASS


def test_cookie_attribute_names_are_case_insensitive():
    resp = make_response("https://example.com/", headers=[("Set-Cookie", "sid=1; SECURE; HTTPONLY; SAMESITE=Strict")])
    assert "cookies.sid.ok" in ids(CookiesCheck().analyze(resp))


def test_server_name_without_version_is_not_a_leak():
    """'nginx' or 'cloudflare' alone is not version disclosure (false positive guard)."""
    for server in ("nginx", "cloudflare", "Apache", "Microsoft-IIS"):
        results = ids(DisclosureCheck().analyze_headers(Headers.from_pairs([("Server", server)])))
        assert results["disclosure.versions"].status is Status.PASS, server


def test_version_in_second_server_header_is_found():
    """Some stacks send two Server headers; the second one leaked in our own demo."""
    headers = Headers.from_pairs([("Server", "proxy"), ("Server", "Apache/2.4.41")])
    assert "Apache/2.4.41" in ids(DisclosureCheck().analyze_headers(headers))["disclosure.versions"].evidence


def test_security_txt_served_as_json_soft_404_is_not_accepted(make_ctx):
    base, sec = "https://example.com/", "https://example.com/.well-known/security.txt"
    ctx = make_ctx(
        "example.com",
        {
            base: make_response(base),
            sec: make_response(sec, status=404, headers={"Content-Type": "text/plain"}, body=b"Contact: nobody"),
        },
    )
    assert "disclosure.security_txt.missing" in ids(DisclosureCheck().run(ctx))
