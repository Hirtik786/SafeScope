# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- The PyPI distribution is named `safescope-scanner` (`safescope` was already taken).
  The command and the import name stay `safescope`.
- Releases publish to PyPI through Trusted Publishing (OIDC), with no stored token.

## [0.2.0] - 2026-11-20

### Security
- **Fixed a DNS rebinding bypass of the web service's SSRF guard.** The guard
  resolved the host, then the HTTP client and TLS inspector connected by name,
  so a second DNS answer (for example `127.0.0.1`) could be used. Connections
  are now pinned to the validated address while `Host`, SNI and certificate
  checks keep the original name. Regression tests reproduce the attack.
- Hosts that resolve to a mix of public and private addresses are refused.
- API error messages no longer include resolved addresses.
- Web service limits: 25 s per scan, 4 concurrent scans per instance (`503`
  with `Retry-After`), `Retry-After` on `429`.
- `X-Forwarded-For` is only trusted where the proxy overwrites it (Vercel);
  `safescope serve` gained `--trust-proxy`.
- Targets with credentials, invalid ports, invalid host names, whitespace or
  control characters are rejected.

### Added
- Scan several targets: `safescope scan a.com b.com --targets-file FILE`,
  in parallel with `--concurrency` (1–16, default 4).
- `--max-time` to cap the total duration of one target's scan.
- SARIF 2.1.0 output (`-f sarif`) with `security-severity` for GitHub code scanning.
- `safescope report FILE.json` re-renders a saved scan in any format.
- `skipped` status for tests that could not run (never counted as a pass).
- `confidence` on every finding (`medium` for name-based cookie heuristics).
- `schema_version` in JSON reports.
- Docs: check catalogue, architecture, security model, FAQ, acceptable use,
  baseline; feature-request and security-question issue templates.

### Changed
- `tls.handshake` and `tls.protocol.legacy_untested` are now `skipped`
  instead of `info`.
- Evidence is capped at 300 characters.
- Reports state that a grade is not proof of security.
- Multi-target JSON is `{"schema_version", "tool", "results": [...]}`;
  single-target JSON is unchanged apart from the new fields.
- Exit code 3 now means "a target was unreachable"; other targets are still reported.

### CI
- GitHub Actions upgraded to v7; `ruff format` enforced; 85% coverage gate;
  wheel install test in a clean environment; GitHub Action self-test;
  real-world scans retry once on network errors.

## [0.1.0] - 2026-11-20

### Added
- `transport` check: HTTPS availability, HTTP→HTTPS redirect, HTTPS downgrade, HSTS policy.
- `tls` check: certificate trust and host name, expiry warnings, negotiated protocol,
  TLS 1.0/1.1 support detection.
- `headers` check: CSP (including unsafe sources), clickjacking protection,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, deprecated `X-XSS-Protection`.
- `cookies` check: `Secure`, `HttpOnly`, `SameSite` attributes.
- `disclosure` check: version banners, CORS wildcard with credentials, `security.txt`.
- 0–100 score and A+→F grade.
- Console, JSON, Markdown and self-contained HTML reports.
- `safescope` CLI with `--fail-on` for CI, and a GitHub Action.
- Deliberately misconfigured demo server for safe local testing.
- Web UI and JSON API (`safescope serve`), deployable to Vercel.
- SSRF guard (`--public-only` on the CLI, always on in the web app) applied to every
  connection, redirect hop and TLS handshake.
- Per-IP rate limiting for the web API.
- Detection of servers that only support deprecated TLS 1.0/1.1.
- Scans continue when the certificate is untrusted (reported by the `tls` check).
- Real-world test suite against badssl.com and major sites (`pytest -m network --run-network`).

[Unreleased]: https://github.com/Karim-Bazooka/SafeScope/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Karim-Bazooka/SafeScope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Karim-Bazooka/SafeScope/releases/tag/v0.1.0
