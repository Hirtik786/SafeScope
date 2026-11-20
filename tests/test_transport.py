from __future__ import annotations

from conftest import make_response

from safescope.checks.transport import TransportCheck, parse_hsts
from safescope.models import Severity, Status


def run(make_ctx, routes, target="example.com"):
    return {f.id: f for f in TransportCheck().run(make_ctx(target, routes))}


def test_parse_hsts():
    assert parse_hsts('max-age="300"; includeSubDomains; preload') == {
        "max-age": "300",
        "includesubdomains": True,
        "preload": True,
    }


def test_ideal_setup(make_ctx):
    routes = {
        "https://example.com/": make_response(
            "https://example.com/",
            headers={"Strict-Transport-Security": "max-age=63072000; includeSubDomains"},
        ),
        "http://example.com/": make_response("https://example.com/", chain=[(301, "http://example.com/")]),
    }
    results = run(make_ctx, routes)
    assert set(results) == {
        "transport.https.available",
        "transport.http.redirects",
        "transport.hsts.present",
    }
    assert "301" in results["transport.http.redirects"].evidence


def test_no_https_at_all(make_ctx):
    routes = {"http://example.com/": make_response("http://example.com/")}
    results = run(make_ctx, routes)
    assert results["transport.https.unavailable"].severity is Severity.HIGH
    assert results["transport.http.no_redirect"].status is Status.FAIL
    assert not any(k.startswith("transport.hsts") for k in results)


def test_https_downgrades_to_http(make_ctx):
    routes = {
        "https://example.com/": make_response("http://example.com/", chain=[(302, "https://example.com/")]),
    }
    results = run(make_ctx, routes)
    assert "transport.https.downgrade" in results
    assert "transport.http.closed" in results


def test_hsts_missing_short_invalid_and_no_subdomains(make_ctx):
    def with_hsts(value):
        headers = {"Strict-Transport-Security": value} if value is not None else {}
        return {"https://example.com/": make_response("https://example.com/", headers=headers)}

    assert "transport.hsts.missing" in run(make_ctx, with_hsts(None))
    assert "transport.hsts.short" in run(make_ctx, with_hsts("max-age=600"))
    assert "transport.hsts.invalid" in run(make_ctx, with_hsts("includeSubDomains"))
    assert "transport.hsts.invalid" in run(make_ctx, with_hsts("max-age=-1"))
    assert "transport.hsts.subdomains" in run(make_ctx, with_hsts("max-age=31536000"))


def test_explicit_port_is_preserved(make_ctx):
    ctx = make_ctx("http://localhost:8080/app?x=1", {})
    assert ctx.https_url() == "https://localhost:8080/app?x=1"
    assert ctx.http_url() == "http://localhost:8080/app?x=1"
    ctx = make_ctx("https://example.com:443/", {})
    assert ctx.http_url() == "http://example.com/"
