"""SARIF 2.1.0 output, the standard format for static-analysis style results.

One run per scanned target. Only problems (fail/warn) become results; each
finding ID becomes a rule so tools can group and suppress findings.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from safescope.models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/Karim-Bazooka/SafeScope"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning reads this rule property to rank security alerts (0.0-10.0).
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def _rule(f: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": f.id,
        "name": f.id.replace(".", "_"),
        "shortDescription": {"text": f.title},
        "properties": {"tags": ["security", f.check_id], "security-severity": SECURITY_SEVERITY[f.severity]},
    }
    if f.description:
        rule["fullDescription"] = {"text": f.description}
    if f.recommendation:
        rule["help"] = {"text": f.recommendation}
    if f.references:
        rule["helpUri"] = f.references[0]
    return rule


def _run(result: ScanResult) -> dict[str, Any]:
    problems = result.problems
    rules: dict[str, dict[str, Any]] = {}
    for f in problems:
        rules.setdefault(f.id, _rule(f))
    rule_index = {rule_id: i for i, rule_id in enumerate(rules)}
    results = []
    for f in problems:
        text = f.title + (f" Fix: {f.recommendation}" if f.recommendation else "")
        results.append(
            {
                "ruleId": f.id,
                "ruleIndex": rule_index[f.id],
                "level": LEVEL[f.severity],
                "message": {"text": text},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.final_url or result.target}}}],
                "properties": {
                    "severity": f.severity.label,
                    "confidence": f.confidence.value,
                    "evidence": f.evidence,
                },
            }
        )
    return {
        "tool": {
            "driver": {
                "name": "SafeScope",
                "version": result.tool_version,
                "informationUri": INFO_URI,
                "rules": list(rules.values()),
            }
        },
        "results": results,
        "properties": {"target": result.target, "grade": result.grade, "score": result.score},
    }


def render_sarif_many(results: Sequence[ScanResult]) -> str:
    log = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [_run(r) for r in results]}
    return json.dumps(log, indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: ScanResult) -> str:
    return render_sarif_many([result])
