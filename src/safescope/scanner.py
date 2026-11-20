"""Orchestrates checks against a single target."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone

from safescope._version import __version__
from safescope.checks import Check, get_checks
from safescope.context import ScanContext
from safescope.http import FetchError, HttpClient
from safescope.models import Finding, ScanResult, Severity, Status
from safescope.scoring import score

ProgressCallback = Callable[[Check], None]


class Scanner:
    def __init__(
        self,
        checks: list[Check] | None = None,
        client: HttpClient | None = None,
        on_check_start: ProgressCallback | None = None,
    ) -> None:
        self.checks = checks if checks is not None else get_checks()
        self.client = client or HttpClient()
        self.on_check_start = on_check_start

    def scan(self, target: str, context: ScanContext | None = None) -> ScanResult:
        ctx = context or ScanContext(target, client=self.client)
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()

        findings: list[Finding] = []
        for check in self.checks:
            if self.on_check_start:
                self.on_check_start(check)
            try:
                findings.extend(check.run(ctx))
            except Exception as exc:  # a buggy check must not hide the other results
                findings.append(
                    Finding(
                        id=f"{check.id}.crash",
                        check_id=check.id,
                        title=f"Check '{check.name}' crashed",
                        status=Status.ERROR,
                        severity=Severity.INFO,
                        description=f"{exc.__class__.__name__}: {exc}",
                        recommendation="Please report this at https://github.com/Karim-Bazooka/SafeScope/issues",
                    )
                )

        try:
            final = ctx.main_response()
            final_url, metadata = (
                final.url,
                {
                    "status": final.status,
                    "redirects": [{"status": s, "url": u} for s, u in final.redirect_chain],
                    "server": final.headers.get("Server") or "",
                    "certificate_verified": not ctx.insecure_fallback,
                },
            )
        except FetchError as exc:
            final_url = ctx.target
            metadata = {
                "error": str(exc),
                # Safe to show to anonymous users of the web API (no resolved addresses).
                "error_public": getattr(exc, "public_message", str(exc)),
                "blocked": exc.__class__.__name__ == "BlockedTargetError",
            }

        value, grade = score(findings)
        return ScanResult(
            target=ctx.target,
            final_url=final_url,
            started_at=started.isoformat(timespec="seconds"),
            duration_seconds=time.perf_counter() - t0,
            findings=findings,
            score=value,
            grade=grade,
            tool_version=__version__,
            metadata=metadata,
        )


def scan(target: str, **kwargs: object) -> ScanResult:
    """Convenience API: ``safescope.scan("example.com")``."""
    return Scanner(**kwargs).scan(target)  # type: ignore[arg-type]
