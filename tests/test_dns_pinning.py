"""Regression tests for DNS rebinding (roadmap phase 1).

Threat: the guard resolves ``rebind.example`` to a public IP and allows it, then
the socket resolves the name *again* and gets 127.0.0.1. These tests simulate
exactly that with a fake resolver whose answer changes after the first lookup,
and assert that the real connection goes to the address that was validated.
"""

from __future__ import annotations

import socket

import pytest

from safescope.context import ScanContext
from safescope.http import FetchError, HttpClient
from safescope.netguard import BlockedTargetError, assert_public_url, resolve_public_host

PUBLIC = "93.184.215.14"


@pytest.fixture
def rebinding_dns(monkeypatch):
    """First lookup answers a public IP, every later lookup answers 127.0.0.1."""
    lookups: list[str] = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        lookups.append(host)
        ip = PUBLIC if len(lookups) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return lookups


@pytest.fixture
def recorded_connections(monkeypatch):
    """Record where sockets would connect, without touching the network."""
    connections: list[tuple[str, int]] = []

    def fake_create_connection(address, timeout=None, source_address=None, *args, **kwargs):
        connections.append((address[0], address[1]))
        raise OSError("blocked in test")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    return connections


def test_http_connection_uses_the_validated_address(rebinding_dns, recorded_connections):
    with pytest.raises(FetchError):
        HttpClient(timeout=1, url_guard=assert_public_url).get("http://rebind.example/")
    # Old behaviour connected to ("rebind.example", 80) and let the OS re-resolve it.
    assert recorded_connections == [(PUBLIC, 80)]
    assert rebinding_dns == ["rebind.example"]  # resolved exactly once


def test_https_connection_uses_the_validated_address(rebinding_dns, recorded_connections):
    with pytest.raises(FetchError):
        HttpClient(timeout=1, url_guard=assert_public_url).get("https://rebind.example/")
    assert recorded_connections == [(PUBLIC, 443)]


def test_tls_inspection_uses_the_validated_address(rebinding_dns, recorded_connections):
    ctx = ScanContext("https://rebind.example/", client=HttpClient(timeout=1, url_guard=assert_public_url))
    info = ctx.tls_info()
    assert not info.connected
    assert recorded_connections and all(addr == (PUBLIC, 443) for addr in recorded_connections)


def test_without_a_guard_the_cli_still_connects_by_name(recorded_connections):
    """The CLI (no guard) keeps normal OS resolution so private staging hosts work."""
    with pytest.raises(FetchError):
        HttpClient(timeout=1).get("http://staging.internal/")
    assert recorded_connections == [("staging.internal", 80)]


def test_resolve_public_host_returns_a_validated_address(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", port, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_public_host("dual.example", 443) == "2606:4700:4700::1111"


def test_mixed_answers_are_refused_even_if_the_first_is_public(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(BlockedTargetError):
        resolve_public_host("mixed.example", 80)


def test_blocked_error_has_a_public_message_without_addresses():
    with pytest.raises(BlockedTargetError) as info:
        assert_public_url("http://10.1.2.3/")
    assert "10.1.2.3" in str(info.value)  # detailed for the CLI / logs
    assert "10.1.2.3" not in info.value.public_message  # safe for API responses
