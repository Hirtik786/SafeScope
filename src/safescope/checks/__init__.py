"""Registry of all built-in checks."""

from __future__ import annotations

from safescope.checks.base import Check
from safescope.checks.cookies import CookiesCheck
from safescope.checks.disclosure import DisclosureCheck
from safescope.checks.headers import HeadersCheck
from safescope.checks.tls_check import TLSCheck
from safescope.checks.transport import TransportCheck

ALL_CHECKS: tuple[type[Check], ...] = (
    TransportCheck,
    TLSCheck,
    HeadersCheck,
    CookiesCheck,
    DisclosureCheck,
)


def get_checks(only: list[str] | None = None, skip: list[str] | None = None) -> list[Check]:
    known = {c.id for c in ALL_CHECKS}
    for name in (only or []) + (skip or []):
        if name not in known:
            raise ValueError(f"unknown check {name!r} (available: {', '.join(sorted(known))})")
    selected = [c for c in ALL_CHECKS if (not only or c.id in only) and c.id not in (skip or [])]
    return [cls() for cls in selected]


__all__ = ["ALL_CHECKS", "Check", "get_checks"]
