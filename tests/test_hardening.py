"""Service limits and input validation (roadmap phase 2)."""

from __future__ import annotations

import json
import time

import pytest

from safescope import web
from safescope.context import normalize_target
from safescope.http import FetchError, HttpClient
from safescope.web import RateLimiter, client_ip, handle_scan

# --- input validation -------------------------------------------------------


@pytest.mark.parametrize(
    "raw, reason",
    [
        ("https://user:secret@example.com/", "password"),
        ("https://admin@example.com/", "user name"),
        ("https://example.com:99999/", "invalid port"),
        ("https://exa mple.com/", "spaces"),
        ("https://example.com/\x00", "control"),
        ("https://-bad-.example.com/", "not a valid host"),
        ("https://exa_mple.com/", "not a valid host"),
        ("https://" + "a" * 64 + ".com/", "not a valid host"),
    ],
)
def test_malformed_targets_are_rejected(raw, reason):
    with pytest.raises(ValueError, match=reason):
        normalize_target(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "example.com",
        "https://sub.example.co.uk/path?q=1",
        "http://[2606:4700::1]:8080/",
        "https://bücher.de/",
        "1.1.1.1",
    ],
)
def test_valid_targets_are_accepted(raw):
    assert normalize_target(raw).startswith(("http://", "https://"))


def test_web_api_rejects_credentials_in_url():
    resp = web.handle_scan("target=https://u:p@example.com", "1.1.1.1", limiter=RateLimiter())
    assert resp.status == 400
    assert b"secret" not in resp.body


# --- client IP trust ----------------------------------------------------------


def headers(**values):
    lowered = {k.replace("_", "-").lower(): v for k, v in values.items()}
    return lambda name: lowered.get(name.lower())


def test_spoofed_forwarded_for_is_ignored_without_a_trusted_proxy():
    get = headers(x_forwarded_for="6.6.6.6")
    assert client_ip(get, "203.0.113.9", trust_proxy_headers=False) == "203.0.113.9"


def test_forwarded_for_is_used_behind_a_trusted_proxy():
    get = headers(x_forwarded_for="198.51.100.4, 10.0.0.1")
    assert client_ip(get, "10.0.0.1", trust_proxy_headers=True) == "198.51.100.4"


def test_trusted_proxy_without_header_falls_back_to_peer():
    assert client_ip(headers(), "10.0.0.1", trust_proxy_headers=True) == "10.0.0.1"


# --- concurrency and time budget ---------------------------------------------


def test_busy_scanner_answers_503(monkeypatch):
    class AlwaysBusy:
        def acquire(self, blocking=True):
            return False

        def release(self):
            raise AssertionError("must not release a slot it never took")

    monkeypatch.setattr(web, "_SCAN_SLOTS", AlwaysBusy())
    monkeypatch.setattr(web, "assert_public_url", lambda url: "93.184.215.14")
    resp = handle_scan("target=example.com", "1.1.1.1", limiter=RateLimiter())
    assert resp.status == 503
    assert ("Retry-After", "5") in resp.headers


def test_slot_is_released_even_when_the_scan_crashes(monkeypatch):
    from safescope import scanner as scanner_mod

    def boom(self, target, context=None):
        raise RuntimeError("crash")

    monkeypatch.setattr(web, "assert_public_url", lambda url: "93.184.215.14")
    monkeypatch.setattr(scanner_mod.Scanner, "scan", boom)
    for _ in range(web.MAX_CONCURRENT_SCANS + 1):
        with pytest.raises(RuntimeError):
            handle_scan("target=example.com", "1.1.1.1", limiter=RateLimiter())
    assert web._SCAN_SLOTS.acquire(blocking=False)  # still available
    web._SCAN_SLOTS.release()


def test_time_budget_caps_every_request():
    client = HttpClient(timeout=10, budget=0.05)
    assert client.remaining_timeout() <= 0.05
    time.sleep(0.06)
    with pytest.raises(FetchError, match="budget"):
        client.get("http://127.0.0.1:9/")


def test_rate_limited_response_has_retry_after():
    rl = RateLimiter(limit=0)
    resp = handle_scan("target=example.com", "1.1.1.1", limiter=rl)
    assert resp.status == 429
    assert ("Retry-After", "60") in resp.headers
    assert json.loads(resp.body)["error"]


def test_api_sends_no_cors_headers():
    resp = handle_scan("", "1.1.1.1", limiter=RateLimiter())
    assert not any(name.lower().startswith("access-control-") for name, _ in resp.headers)
