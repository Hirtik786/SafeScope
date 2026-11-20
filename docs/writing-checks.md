# Writing a check

A check is a small class that receives a `ScanContext` and returns a list of `Finding`s.
This guide builds a real example: flagging pages that do not declare a character set.

## 1. Create the module

`src/safescope/checks/charset.py`:

```python
from __future__ import annotations

from safescope.checks.base import Check
from safescope.context import ScanContext
from safescope.http import FetchError, Headers
from safescope.models import Finding, Severity, Status


class CharsetCheck(Check):
    id = "charset"  # stable, used by --only / --skip
    name = "Character set"
    description = "Ensures HTML responses declare their character encoding."

    def run(self, ctx: ScanContext) -> list[Finding]:
        try:
            resp = ctx.main_response()  # cached: no extra request
        except FetchError as exc:
            return [self.error("fetch", "Could not fetch the page", str(exc))]
        return self.analyze(resp.headers)

    def analyze(self, headers: Headers) -> list[Finding]:
        content_type = headers.get("Content-Type") or ""
        if "charset=" in content_type.lower():
            return [self.passed("declared", "Character set is declared", content_type)]
        return [
            self.finding(
                "missing",
                "Content-Type has no charset",
                Status.WARN,
                Severity.LOW,
                description="Browsers may guess the encoding, which has enabled XSS in the past.",
                recommendation="Send 'Content-Type: text/html; charset=utf-8'.",
                evidence=content_type,
            )
        ]
```

Key points:

- **Never call the network yourself.** Use `ctx.main_response()`, `ctx.fetch(url)`,
  `ctx.fetch_path("/path")` or `ctx.tls_info()`. Responses are cached, so many checks can share
  one request.
- **Split I/O from logic.** `run()` fetches, `analyze()` decides. `analyze()` is then trivial to
  test.
- **Don't raise on network errors.** Return `self.error(...)` instead. If a check crashes
  anyway, the scanner records it and continues.
- **Finding IDs** are `<check id>.<suffix>`; keep them stable because users track them.
- **Severity** reflects real-world impact. When in doubt, choose the lower one and explain in
  the PR.

## 2. Register it

Add the class to `ALL_CHECKS` in `src/safescope/checks/__init__.py`.

## 3. Test it

```python
from safescope.checks.charset import CharsetCheck
from safescope.http import Headers


def test_charset_missing():
    findings = CharsetCheck().analyze(Headers.from_pairs([("Content-Type", "text/html")]))
    assert findings[0].id == "charset.missing"
```

To test `run()` without a network, use the `make_ctx` fixture from `tests/conftest.py`, which
serves canned responses.

## 4. Document it

Add a row to the *What it checks* table in `README.md` and an entry in `CHANGELOG.md`.
