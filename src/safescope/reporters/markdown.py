"""Markdown output - handy for GitHub Actions job summaries and PR comments."""

from __future__ import annotations

from safescope.models import ScanResult, Status

ICON = {
    Status.PASS: "✅",
    Status.FAIL: "❌",
    Status.WARN: "⚠️",
    Status.INFO: "ℹ️",
    Status.SKIPPED: "⏭️",
    Status.ERROR: "💥",
}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    out = [
        f"## SafeScope report for `{result.target}`",
        "",
        f"**Grade: {result.grade}** · score {result.score}/100 · "
        f"scanned {result.started_at} with SafeScope v{result.tool_version}",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        "| " + " | ".join(str(n) for n in result.counts().values()) + " |",
        "",
        "| | Check | Finding | Severity | Recommendation |",
        "|---|---|---|---|---|",
    ]
    ordered = sorted(result.findings, key=lambda f: (not f.is_problem, -f.severity, f.check_id))
    for f in ordered:
        sev = f.severity.label if f.is_problem else ""
        rec = f.recommendation if f.is_problem else ""
        out.append(f"| {ICON[f.status]} | {f.check_id} | {_cell(f.title)} | {sev} | {_cell(rec)} |")
    out += ["", "_The grade summarises passive checks; it is not proof that a site is secure._"]
    return "\n".join(out) + "\n"
