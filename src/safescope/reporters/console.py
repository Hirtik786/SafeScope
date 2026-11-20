"""Human friendly terminal output with optional ANSI colours."""

from __future__ import annotations

import os
import sys
import textwrap

from safescope.models import Finding, ScanResult, Severity, Status

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}

STATUS_STYLE = {
    Status.PASS: ("PASS", "green"),
    Status.FAIL: ("FAIL", "red"),
    Status.WARN: ("WARN", "yellow"),
    Status.INFO: ("INFO", "blue"),
    Status.SKIPPED: ("SKIP", "cyan"),
    Status.ERROR: ("ERR ", "magenta"),
}
SEVERITY_COLOR = {
    Severity.CRITICAL: "magenta",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


def supports_color(stream: object = None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    isatty = getattr(stream or sys.stdout, "isatty", None)
    return bool(isatty and isatty())


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, color: str | None = None, bold: bool = False, dim: bool = False) -> str:
        if not self.enabled:
            return text
        prefix = (BOLD if bold else "") + (DIM if dim else "") + (COLORS[color] if color else "")
        return f"{prefix}{text}{RESET}" if prefix else text


def _grade_color(grade: str) -> str:
    return {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}[grade[0]]


def render_console(result: ScanResult, color: bool | None = None, verbose: bool = False) -> str:
    paint = _Painter(supports_color() if color is None else color)
    lines: list[str] = []
    width = 72

    lines.append(paint("SafeScope", "cyan", bold=True) + paint(f" v{result.tool_version}", dim=True))
    lines.append(f"Target : {result.target}")
    if result.final_url and result.final_url != result.target:
        lines.append(f"Landed : {result.final_url}")
    lines.append(
        "Grade  : "
        + paint(f" {result.grade} ", _grade_color(result.grade), bold=True)
        + f"  score {result.score}/100  ({result.duration_seconds:.1f}s)"
    )
    lines.append("")

    by_check: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_check.setdefault(f.check_id, []).append(f)

    for check_id, findings in by_check.items():
        lines.append(paint(check_id.upper(), bold=True))
        for f in findings:
            label, col = STATUS_STYLE[f.status]
            sev = ""
            if f.is_problem and f.severity > Severity.INFO:
                sev = " " + paint(f"[{f.severity.label}]", SEVERITY_COLOR[f.severity])
            lines.append(f"  {paint(label, col, bold=True)} {f.title}{sev}")
            show_details = f.is_problem or f.status in (Status.ERROR, Status.SKIPPED) or verbose
            if show_details:
                details = [(f.evidence, "· ", True)]
                if f.is_problem:
                    details.append((f.recommendation, "↳ ", False))
                for text, marker, dim in details:
                    if not text:
                        continue
                    wrapped = textwrap.wrap(text, width=width - 9) or [""]
                    lines.append(paint("       " + marker + wrapped[0], dim=dim))
                    lines.extend(paint("         " + w, dim=dim) for w in wrapped[1:])
                if f.status in (Status.ERROR, Status.SKIPPED) and f.description:
                    lines.append(paint("       · " + f.description, dim=True))
        lines.append("")

    counts = result.counts()
    summary = "  ".join(
        paint(f"{n} {name}", SEVERITY_COLOR[Severity.parse(name)] if n else None, dim=not n)
        for name, n in counts.items()
    )
    lines.append("Issues : " + summary)
    lines.append(paint("The grade summarises passive checks; it is not proof that a site is secure.", dim=True))
    lines.append(paint("Only scan sites you own or are authorised to test.", dim=True))
    return "\n".join(lines) + "\n"
