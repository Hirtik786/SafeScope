# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Karim-Bazooka/SafeScope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Karim-Bazooka/SafeScope/releases/tag/v0.1.0
