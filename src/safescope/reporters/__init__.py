"""Output formats. Each reporter is a function ``(ScanResult) -> str``."""

from __future__ import annotations

from collections.abc import Callable

from safescope.models import ScanResult
from safescope.reporters.console import render_console
from safescope.reporters.html import render_html
from safescope.reporters.json import render_json
from safescope.reporters.markdown import render_markdown
from safescope.reporters.sarif import render_sarif

Reporter = Callable[[ScanResult], str]

REPORTERS: dict[str, Reporter] = {
    "console": render_console,
    "json": render_json,
    "html": render_html,
    "markdown": render_markdown,
    "sarif": render_sarif,
}

__all__ = ["REPORTERS", "Reporter", "render_console", "render_html", "render_json", "render_markdown", "render_sarif"]
