from __future__ import annotations

import json

from safescope.models import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"
