from __future__ import annotations

from conftest import make_response

from safescope.checks.cookies import CookiesCheck, parse_set_cookie
from safescope.checks.disclosure import DisclosureCheck
from safescope.http import Headers
from safescope.models import Severity, Status

# --- cookies -----------------------------------------------------------------


def test_parse_set_cookie_drops_value():
    c = parse_set_cookie("sessionid=SECRET; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c.name == "sessionid"
    assert c.secure and c.http_only and c.same_site == "lax"
    assert "SECRET" not in repr(c)


def cookie_findings(cookies, url="https://example.com/"):
    resp = make_response(url, headers=[("Set-Cookie", c) for c in cookies])
    return {f.id: f for f in CookiesCheck().analyze(resp)}


def test_no_cookies_is_info():
    assert cookie_findings([])["cookies.none"].status is Status.INFO


def test_well_configured_cookie():
    results = cookie_findings(["sid=1; Secure; HttpOnly; SameSite=Strict"])
    assert results["cookies.sid.ok"].status is Status.PASS


def test_insecure_session_cookie_is_medium():
    f = cookie_findings(["PHPSESSID=abc; Path=/"])["cookies.PHPSESSID.flags"]
    assert f.severity is Severity.MEDIUM
    assert "missing Secure" in f.title and "missing HttpOnly" in f.title


def test_non_sensitive_cookie_does_not_need_httponly():
    f = cookie_findings(["theme=dark; Secure; SameSite=Lax"])
    assert "cookies.theme.ok" in f


def test_samesite_none_requires_secure():
    f = cookie_findings(["tracking=1; SameSite=None"], url="http://example.com/")
    assert "SameSite=None without Secure" in f["cookies.tracking.flags"].title


def test_secure_flag_not_required_on_plain_http():
    f = cookie_findings(["theme=dark; SameSite=Lax"], url="http://example.com/")
    assert "cookies.theme.ok" in f


# --- disclosure --------------------------------------------------------------


def disclosure(headers):
    return {f.id: f for f in DisclosureCheck().analyze_headers(Headers.from_pairs(headers.items()))}


def test_version_banners_are_reported():
    f = disclosure({"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"})
    assert "Apache/2.4.41" in f["disclosure.versions"].evidence
    assert "PHP/7.4.3" in f["disclosure.versions"].evidence


def test_plain_server_name_is_fine():
    assert disclosure({"Server": "cloudflare"})["disclosure.versions"].status is Status.PASS


def test_cors_wildcard_with_credentials():
    f = disclosure({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert f["disclosure.cors.wildcard_credentials"].status is Status.FAIL
    assert disclosure({"Access-Control-Allow-Origin": "*"})["disclosure.cors.wildcard"].status is Status.INFO


def test_security_txt_found_and_missing(make_ctx):
    base = "https://example.com/"
    sec = "https://example.com/.well-known/security.txt"
    ok = make_ctx(
        "example.com",
        {
            base: make_response(base),
            sec: make_response(
                sec,
                headers={"Content-Type": "text/plain"},
                body=b"Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n",
            ),
        },
    )
    f = {x.id: x for x in DisclosureCheck().run(ok)}
    assert f["disclosure.security_txt"].evidence == "mailto:security@example.com"

    # Many sites answer every path with their HTML home page; that is not a security.txt.
    soft404 = make_ctx(
        "example.com",
        {
            base: make_response(base),
            sec: make_response(sec, headers={"Content-Type": "text/html"}, body=b"<p>Contact: us</p>"),
        },
    )
    f = {x.id: x for x in DisclosureCheck().run(soft404)}
    assert "disclosure.security_txt.missing" in f
