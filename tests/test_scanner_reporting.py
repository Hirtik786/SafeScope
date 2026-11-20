from __future__ import annotations

import json

import pytest
from conftest import GOOD_HEADERS, make_response

from safescope.checks.base import Check
from safescope.context import normalize_target
from safescope.models import Finding, Severity, Status
from safescope.reporters import render_console, render_html, render_json, render_markdown
from safescope.scanner import Scanner
from safescope.scoring import score


def F(sev: Severity, status: Status = Status.FAIL) -> Finding:
    return Finding(id="x.y", check_id="x", title="t", status=status, severity=sev)


# --- target normalisation ------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "https://example.com/"),
        ("  http://Example.com:8080/a?b=1#frag ", "http://Example.com:8080/a?b=1"),
        ("https://example.com/path", "https://example.com/path"),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "ftp://example.com", "https://"])
def test_normalize_target_rejects(raw):
    with pytest.raises(ValueError):
        normalize_target(raw)


# --- scoring -------------------------------------------------------------------


def test_scoring_bands_and_caps():
    assert score([]) == (100, "A+")
    assert score([F(Severity.LOW)]) == (97, "A+")
    assert score([F(Severity.MEDIUM)] * 2) == (80, "B")
    assert score([F(Severity.HIGH)]) == (80, "C")  # capped by a HIGH issue
    assert score([F(Severity.CRITICAL)]) == (60, "F")  # any critical is an F
    assert score([F(Severity.HIGH)] * 6) == (0, "F")
    assert score([F(Severity.HIGH, Status.PASS)]) == (100, "A+")  # passes never cost points


# --- scanner -------------------------------------------------------------------


class Boom(Check):
    id = "boom"
    name = "Boom"
    description = "always crashes"

    def run(self, ctx):
        raise RuntimeError("kaboom")


def full_ctx(make_ctx):
    url = "https://example.com/"
    return make_ctx(
        "example.com",
        {
            url: make_response(url, headers={**GOOD_HEADERS, "Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Lax"}),
            "http://example.com/": make_response(url, chain=[(301, "http://example.com/")]),
        },
    )


def test_scanner_end_to_end_with_fakes(make_ctx):
    ctx = full_ctx(make_ctx)
    result = Scanner().scan(ctx.target, context=ctx)
    assert result.final_url == "https://example.com/"
    assert result.grade == "A+", [f.id for f in result.problems]
    # each URL fetched once even though several checks need the main page
    assert ctx.client.calls.count("https://example.com/") == 1


def test_crashing_check_is_isolated(make_ctx):
    ctx = full_ctx(make_ctx)
    result = Scanner(checks=[Boom()]).scan(ctx.target, context=ctx)
    assert result.findings[0].id == "boom.crash"
    assert result.findings[0].status is Status.ERROR
    assert "kaboom" in result.findings[0].description


def test_unreachable_target_sets_error_metadata(make_ctx):
    ctx = make_ctx("nowhere.invalid", {})
    result = Scanner().scan(ctx.target, context=ctx)
    assert "error" in result.metadata


# --- reporters -----------------------------------------------------------------


def sample_result(make_ctx):
    url = "https://example.com/"
    ctx = make_ctx(
        "example.com",
        {url: make_response(url, headers={"Server": "<script>alert(1)</script>/1.0", "Set-Cookie": "PHPSESSID=x"})},
    )
    return Scanner().scan(ctx.target, context=ctx)


def test_json_report_round_trips(make_ctx):
    data = json.loads(render_json(sample_result(make_ctx)))
    assert data["tool"]["name"] == "SafeScope"
    assert data["summary"]["medium"] >= 1
    assert {"id", "status", "severity", "recommendation"} <= set(data["findings"][0])


def test_html_report_escapes_untrusted_values(make_ctx):
    html = render_html(sample_result(make_ctx))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert html.startswith("<!DOCTYPE html>")


def test_markdown_and_console(make_ctx):
    result = sample_result(make_ctx)
    md = render_markdown(result)
    assert md.startswith("## SafeScope report")
    text = render_console(result, color=False)
    assert "Grade" in text and "\033[" not in text
    assert "\033[" in render_console(result, color=True)


def test_untrusted_certificate_does_not_abort_scan(make_ctx):
    from safescope.http import CertificateError

    url = "https://example.com/"
    ctx = make_ctx("example.com", {url: CertificateError("self-signed certificate")})
    calls = []

    class Insecure:
        def get(self, u, follow_redirects=True):
            calls.append(u)
            return make_response(u, headers=GOOD_HEADERS)

    ctx._insecure_client = lambda: Insecure()  # type: ignore[method-assign]
    assert ctx.main_response().status == 200
    assert ctx.insecure_fallback and calls == [url]


def test_json_has_schema_version_and_confidence(make_ctx):
    data = json.loads(render_json(sample_result(make_ctx)))
    assert data["schema_version"] == 1
    cookie = next(f for f in data["findings"] if f["id"] == "cookies.PHPSESSID.flags")
    assert cookie["confidence"] == "medium"  # name-based heuristic
    assert all(f["confidence"] in ("high", "medium", "low") for f in data["findings"])


def test_long_evidence_is_truncated():
    from safescope.checks.base import MAX_EVIDENCE
    from safescope.checks.headers import HeadersCheck
    from safescope.http import Headers

    findings = HeadersCheck().analyze(Headers.from_pairs([("Content-Security-Policy", "script-src * " + "x" * 5000)]))
    unsafe = next(f for f in findings if f.id == "headers.csp.unsafe")
    assert len(unsafe.evidence) == MAX_EVIDENCE
    assert unsafe.evidence.endswith("…")


def test_reports_state_that_a_grade_is_not_proof_of_security(make_ctx):
    result = sample_result(make_ctx)
    for text in (render_console(result, color=False), render_markdown(result), render_html(result)):
        assert "not proof" in text
