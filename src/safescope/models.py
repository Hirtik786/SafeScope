"""Core data models shared by checks, the scanner and reporters."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


#: Version of the JSON report layout. Bump it on incompatible changes.
SCHEMA_VERSION = 1


class Severity(enum.IntEnum):
    """How much a finding matters. Ordered so that comparisons work (HIGH > LOW)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {choices})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


class Status(str, enum.Enum):
    """Outcome of a single test inside a check.

    ``SKIPPED`` means the test could not be performed (for example the local
    OpenSSL cannot offer TLS 1.0). It is never counted as a pass: a scanner
    must not claim something is fine when it did not look.
    """

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"
    SKIPPED = "skipped"
    ERROR = "error"


class Confidence(str, enum.Enum):
    """How sure SafeScope is about a finding (independent of its severity).

    HIGH: read directly from the response (a header is missing).
    MEDIUM: relies on a heuristic (a cookie *looks* like a session cookie).
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    """One observation produced by a check.

    ``check_id`` identifies the check family (e.g. ``headers``) and ``id`` the
    specific test (e.g. ``headers.csp.missing``) so results are stable and
    machine-readable across versions.
    """

    id: str
    check_id: str
    title: str
    status: Status
    severity: Severity = Severity.INFO
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    references: tuple[str, ...] = ()
    confidence: Confidence = Confidence.HIGH

    @property
    def is_problem(self) -> bool:
        return self.status in (Status.FAIL, Status.WARN)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.label
        data["references"] = list(self.references)
        data["confidence"] = self.confidence.value
        return data


@dataclass
class ScanResult:
    """Everything a reporter needs to render a scan."""

    target: str
    final_url: str
    started_at: str
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"
    tool_version: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def problems(self) -> list[Finding]:
        return [f for f in self.findings if f.is_problem]

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.problems:
            out[f.severity.label] += 1
        return out

    def max_severity(self) -> Severity | None:
        problems = self.problems
        return max((f.severity for f in problems), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "SafeScope", "version": self.tool_version},
            "target": self.target,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "score": self.score,
            "grade": self.grade,
            "summary": self.counts(),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Rebuild a result from :meth:`to_dict` output (e.g. a saved JSON report).

        Raises ValueError with a readable message for files that are not
        SafeScope reports or use an unsupported schema version.
        """
        if not isinstance(data, dict) or data.get("tool", {}).get("name") != "SafeScope":
            raise ValueError("not a SafeScope JSON report")
        version = data.get("schema_version", 1)
        if version != SCHEMA_VERSION:
            raise ValueError(f"unsupported report schema_version {version!r} (this SafeScope reads {SCHEMA_VERSION})")
        try:
            findings = [
                Finding(
                    id=str(f["id"]),
                    check_id=str(f["check_id"]),
                    title=str(f["title"]),
                    status=Status(f["status"]),
                    severity=Severity.parse(str(f.get("severity", "info"))),
                    description=str(f.get("description", "")),
                    recommendation=str(f.get("recommendation", "")),
                    evidence=str(f.get("evidence", "")),
                    references=tuple(str(r) for r in f.get("references", [])),
                    confidence=Confidence(f.get("confidence", "high")),
                )
                for f in data.get("findings", [])
            ]
            return cls(
                target=str(data["target"]),
                final_url=str(data.get("final_url", data["target"])),
                started_at=str(data.get("started_at", "")),
                duration_seconds=float(data.get("duration_seconds", 0.0)),
                findings=findings,
                score=int(data["score"]),
                grade=str(data["grade"]),
                tool_version=str(data["tool"].get("version", "")),
                metadata=dict(data.get("metadata", {})),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid SafeScope report: {exc}") from exc
