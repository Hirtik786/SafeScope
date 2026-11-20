"""Base class every check inherits from.

Adding a new check is the most common way to contribute; see
``docs/writing-checks.md`` for a walkthrough.
"""

from __future__ import annotations

import abc
from typing import ClassVar

from safescope.context import ScanContext
from safescope.models import Finding, Severity, Status


class Check(abc.ABC):
    #: short, stable identifier used on the command line (``--only headers``)
    id: ClassVar[str]
    #: human friendly name shown in reports
    name: ClassVar[str]
    #: one sentence describing what the check looks at
    description: ClassVar[str]

    @abc.abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Inspect the target and return findings. Must never raise for
        expected network problems: return an ``Status.ERROR`` finding instead."""

    # -- helpers to keep check code short and consistent ------------------
    def finding(
        self,
        suffix: str,
        title: str,
        status: Status,
        severity: Severity = Severity.INFO,
        *,
        description: str = "",
        recommendation: str = "",
        evidence: str = "",
        references: tuple[str, ...] | list[str] = (),
    ) -> Finding:
        return Finding(
            id=f"{self.id}.{suffix}",
            check_id=self.id,
            title=title,
            status=status,
            severity=severity if status in (Status.FAIL, Status.WARN) else Severity.INFO,
            description=description,
            recommendation=recommendation,
            evidence=evidence,
            references=tuple(references),
        )

    def passed(self, suffix: str, title: str, evidence: str = "") -> Finding:
        return self.finding(suffix, title, Status.PASS, evidence=evidence)

    def error(self, suffix: str, title: str, message: str) -> Finding:
        return self.finding(suffix, title, Status.ERROR, description=message)
