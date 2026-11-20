"""docs/checks.md must list every finding ID the checks can emit."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKS = ROOT / "src" / "safescope" / "checks"
CATALOG = (ROOT / "docs" / "checks.md").read_text(encoding="utf-8")

CALL = re.compile(r'self\.(?:finding|passed|skipped|error)\(\s*f?"([^"]+)"')
CONDITIONAL = re.compile(r'(?:"([a-z_]+(?:\.[a-z_]+)+)" if |else "([a-z_]+(?:\.[a-z_]+)+)")')


def emitted_ids() -> set[str]:
    ids: set[str] = set()
    for path in CHECKS.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        match = re.search(r'^\s+id = "(\w+)"', source, re.M)
        if not match:
            continue
        check_id = match.group(1)
        conditional = [a or b for a, b in CONDITIONAL.findall(source)]
        for suffix in CALL.findall(source) + conditional:
            suffix = re.sub(r"\{c\.name\}", "<name>", suffix)
            ids.add(f"{check_id}.{suffix}")
    return ids


def test_catalog_lists_every_emitted_id():
    ids = emitted_ids()
    assert len(ids) > 40  # sanity: the extraction found the checks
    missing = sorted(i for i in ids if f"`{i}`" not in CATALOG)
    assert not missing, f"add these IDs to docs/checks.md: {missing}"


def test_catalog_has_no_stale_ids():
    listed = set(re.findall(r"`((?:transport|tls|headers|cookies|disclosure)\.[^`]+)`", CATALOG))
    stale = sorted(listed - emitted_ids())
    assert not stale, f"remove or fix these IDs in docs/checks.md: {stale}"
