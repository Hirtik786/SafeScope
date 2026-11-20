# Check catalogue

Every result SafeScope can produce, with its stable ID. IDs are part of the
public interface: they are never renamed within a minor version, so you can
track a finding across scans or suppress it in your own tooling. A test
(`tests/test_catalog.py`) fails if a check emits an ID that is not listed here.

**Status** — `pass` tested and fine · `fail` / `warn` a problem · `info` an
observation · `skipped` could not be tested (never counted as a pass) ·
`error` the check itself failed.
**Confidence** — `high` read directly from the response · `medium` depends on
a heuristic. Severity and confidence are independent: a medium-confidence
finding can still be severe.

## transport — HTTPS & HSTS

| ID | Status | Severity | Meaning |
|---|---|---|---|
| `transport.https.available` | pass | – | The site loads over HTTPS. |
| `transport.https.unavailable` | fail | high | HTTPS could not be loaded; traffic can be read or modified. |
| `transport.https.downgrade` | fail | high | The HTTPS URL redirects to plain HTTP. |
| `transport.http.redirects` | pass | – | Plain HTTP redirects to HTTPS. |
| `transport.http.no_redirect` | fail | medium | Plain HTTP is served without redirecting to HTTPS. |
| `transport.http.closed` | info | – | Port 80 does not answer (safe). |
| `transport.hsts.present` | pass | – | HSTS with max-age ≥ 180 days. |
| `transport.hsts.missing` | fail | medium | No `Strict-Transport-Security` header. |
| `transport.hsts.invalid` | fail | medium | HSTS header without a numeric `max-age`. |
| `transport.hsts.short` | warn | low | `max-age` shorter than 180 days. |
| `transport.hsts.subdomains` | warn | low | HSTS without `includeSubDomains`. |

## tls — TLS & certificate

| ID | Status | Severity | Meaning |
|---|---|---|---|
| `tls.certificate.valid` | pass | – | Trusted chain, matches the host name. |
| `tls.certificate.untrusted` | fail | high | Self-signed, expired, wrong host or incomplete chain. |
| `tls.certificate.expired` | fail | critical | The certificate has expired. |
| `tls.certificate.expiring` | fail / warn | high (≤ 7 days) / low (≤ 30 days) | The certificate expires soon. |
| `tls.certificate.expiry` | pass | – | More than 30 days of validity left. |
| `tls.protocol.modern` | pass | – | TLS 1.2 or 1.3 negotiated. |
| `tls.protocol.outdated` | fail | high | An older protocol was negotiated. |
| `tls.protocol.legacy` | warn | medium | TLS 1.0 or 1.1 is still accepted. |
| `tls.protocol.legacy_only` | fail | high | The server only speaks TLS 1.0/1.1. |
| `tls.protocol.no_legacy` | pass | – | The server refused TLS 1.0 and 1.1 (confirmed by a server alert). |
| `tls.protocol.legacy_untested` | skipped | – | The legacy probe could not run or got no clear answer. |
| `tls.handshake` | skipped | – | No TLS connection could be opened (impact reported by `transport`). |
| `tls.inspect` | error | – | The TLS inspection itself failed. |

## headers — Security headers

| ID | Status | Severity | Meaning |
|---|---|---|---|
| `headers.csp.present` | pass | – | A Content-Security-Policy without unsafe script sources. |
| `headers.csp.missing` | fail | medium | No Content-Security-Policy. |
| `headers.csp.unsafe` | warn | medium | `script-src` allows `'unsafe-inline'` (without nonce/hash), `'unsafe-eval'`, `*` or `data:`. |
| `headers.framing.protected` | pass | – | `frame-ancestors` or `X-Frame-Options: DENY/SAMEORIGIN`. |
| `headers.framing.missing` | fail | medium | No clickjacking protection. |
| `headers.nosniff.present` | pass | – | `X-Content-Type-Options: nosniff`. |
| `headers.nosniff.missing` | fail | low | MIME sniffing not disabled. |
| `headers.referrer.present` | pass | – | A Referrer-Policy that does not leak full URLs. |
| `headers.referrer.missing` | warn | low | No Referrer-Policy. |
| `headers.referrer.weak` | warn | low | Referrer-Policy that may leak full URLs. |
| `headers.permissions.present` | pass | – | A Permissions-Policy is set. |
| `headers.permissions.missing` | warn | low | No Permissions-Policy. |
| `headers.x_xss_protection.enabled` | warn | low | The deprecated XSS auditor is switched on. |
| `headers.fetch` | error | – | The page could not be fetched. |

## cookies — Cookie security

Cookie IDs contain the cookie name: `cookies.<name>.ok` / `cookies.<name>.flags`.
Cookie values are never stored or printed.

| ID | Status | Severity | Confidence | Meaning |
|---|---|---|---|---|
| `cookies.<name>.ok` | pass | – | high | `Secure` (on HTTPS), `SameSite`, and `HttpOnly` if it looks like a session cookie. |
| `cookies.<name>.flags` | fail / warn | low – medium | medium for session-like names | Missing `Secure`, `HttpOnly` or `SameSite`, or `SameSite=None` without `Secure`. |
| `cookies.none` | info | – | high | No cookies on the landing page. |
| `cookies.fetch` | error | – | – | The page could not be fetched. |

## disclosure — Information disclosure

| ID | Status | Severity | Meaning |
|---|---|---|---|
| `disclosure.versions` | pass / warn | low | Software versions in `Server`, `X-Powered-By` and similar headers. |
| `disclosure.cors.wildcard_credentials` | fail | medium | `Access-Control-Allow-Origin: *` together with credentials. |
| `disclosure.cors.wildcard` | info | – | CORS open to every origin (fine for public content). |
| `disclosure.security_txt` | pass | – | `/.well-known/security.txt` with a `Contact:` line. |
| `disclosure.security_txt.missing` | warn | info | No security.txt (advice; costs no points). |
| `disclosure.fetch` | error | – | The page could not be fetched. |

## Any check

| ID | Status | Meaning |
|---|---|---|
| `<check>.crash` | error | The check raised an unexpected exception; the rest of the scan continued. Please report it. |
