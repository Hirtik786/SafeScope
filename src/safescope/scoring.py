"""Turn findings into a 0-100 score and a letter grade.

The model is intentionally simple and documented in docs/scoring.md so users
can understand exactly why they got a grade.
"""

from __future__ import annotations

from collections.abc import Iterable

from safescope.models import Finding, Severity

PENALTY = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

GRADE_BANDS = ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F"))


def score(findings: Iterable[Finding]) -> tuple[int, str]:
    problems = [f for f in findings if f.is_problem]
    value = max(0, 100 - sum(PENALTY[f.severity] for f in problems))
    grade = next(letter for floor, letter in GRADE_BANDS if value >= floor)

    worst = max((f.severity for f in problems), default=Severity.INFO)
    # A single serious issue caps the grade no matter how good the rest is.
    if worst >= Severity.CRITICAL:
        grade = "F"
    elif worst >= Severity.HIGH and grade in ("A+", "A", "B"):
        grade = "C"
    return value, grade
