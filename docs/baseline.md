# Baseline before the v0.2 roadmap (2026-11-20)

Recorded before any roadmap change so later work can be compared against it.

| Item | Value |
|---|---|
| Commit | `7cbd8bc` (main = dev) |
| Released version | 0.1.0 (no GitHub Release yet: tag push blocked from the automation session) |
| Python supported | 3.10 – 3.13 (CI: Ubuntu all four, Windows and macOS on 3.12) |
| Runtime dependencies | none |
| Unit + integration tests | 92 passed, 12 skipped (network tests, opt-in) |
| `ruff check` | passed |
| `ruff format --check` | 16 files would be reformatted (format check was not enforced in CI) |
| `mypy --strict` | passed, 24 source files |
| CI on main | all jobs green (CI + Real-world scans) |
| Live deployment | <https://safescope-one.vercel.app> — self-scan A+ 100/100 |

## Open items found

| # | Item | Severity | Plan phase |
|---|---|---|---|
| 1 | Guard validates DNS, then the socket resolves the host again (DNS rebinding window) | High (web service only) | 1 |
| 2 | Client IP read from `X-Forwarded-For` as a fallback; only safe behind a proxy that overwrites it | Medium | 2 |
| 3 | No overall time budget per scan (each request has its own timeout) | Medium | 2 |
| 4 | No limit on concurrent scans per instance | Medium | 2 |
| 5 | API errors echo resolved IP addresses | Low | 2 |
| 6 | "Could not test" results are reported as `info`, not as an explicit not-tested state | Low | 3 |
| 7 | One real-world CI job failed once with exit code 3 (target unreachable): network flakiness, no retry | Low | 4 |
| 8 | Three Dependabot PRs open (checkout, setup-python, upload-artifact → v7); Node 20 deprecation warning on v4 actions | Low | 4 |
| 9 | Code style not enforced by `ruff format` | Low | 4 |
| 10 | No coverage measurement in CI | Low | 4 |
