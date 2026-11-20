# Security model

This page describes what SafeScope does to stay safe, the limits of the public
web service, and what SafeScope does **not** promise.

## What SafeScope sends to a target

- Only `GET` requests and one TLS handshake per probed protocol version.
- Headers: a `User-Agent` that names SafeScope and links to this repository,
  `Accept`, `Connection: close`. No cookies, no credentials, no payloads.
- At most 10 redirects per URL and the first 256 KB of each body.
- Typically 3–5 HTTP requests and up to 3 TLS handshakes per target.

## Two policies: CLI vs public web service

| | CLI / library (default) | Public web service |
|---|---|---|
| Private, loopback, link-local, CGNAT, multicast addresses | allowed (scanning your own staging host is legitimate) | refused (`--public-only` gives the CLI the same policy) |
| Ports | any | 80, 443, 8080, 8443 |
| Per-request timeout | 10 s (`--timeout`) | 6 s |
| Total time per target | unlimited (`--max-time`) | 25 s |
| Concurrent scans | `--concurrency` (1–16) | 4 per instance, then `503` |
| Rate limit | none | 10 scans/minute per client IP, then `429` |

## SSRF and DNS rebinding

A public scanner can be abused as a proxy into the network it runs in
(Server-Side Request Forgery), for example to read a cloud metadata service at
`169.254.169.254`.

`netguard.assert_public_url` runs before **every** connection: the first request,
each redirect hop, and the TLS inspection. It:

1. accepts only `http`/`https` and the allowed ports;
2. resolves the host **once**;
3. refuses the target if **any** resolved address is not globally routable
   (IPv4-mapped IPv6 addresses are unwrapped first);
4. returns the validated address.

The connection is then made to that exact address (DNS pinning), while the
`Host` header, TLS SNI and certificate verification keep the original name.
Without pinning, the operating system would resolve the name again and an
attacker controlling DNS could answer a public address to the guard and
`127.0.0.1` to the socket (DNS rebinding). `tests/test_dns_pinning.py`
reproduces that attack and fails on the unpinned implementation.

Error messages returned by the API never include resolved addresses.

## Client IP and rate limiting

`X-Forwarded-For` can be set by any client, so it is only used when the
deployment declares that a proxy in front of the app overwrites it:

- **Vercel** overwrites `X-Forwarded-For` and does not forward values sent by
  clients ([Vercel docs](https://vercel.com/docs/headers/request-headers)), so
  `api/scan.py` trusts it.
- **`safescope serve`** uses the TCP peer address unless started with
  `--trust-proxy` (only do that behind nginx/Caddy configured to overwrite the
  header).

Limits are kept in memory, so on serverless platforms each instance counts on
its own. That stops casual abuse; a shared store (for example Redis) would be
needed for strict global limits and is not used today.

## Reports

- Cookie values are never stored or printed; only cookie names and attributes.
- Evidence is capped at 300 characters.
- Every value from the scanned site is HTML-escaped in HTML reports and inserted
  with `textContent` in the web UI, so a malicious site cannot inject script
  into a report.
- The web UI uses a CSP without `unsafe-inline` scripts; the API sends no CORS
  headers; nothing is logged beyond the platform's request logs.

## What SafeScope does not promise

- A good grade means the **passive checks** passed. It is not proof that a site
  is secure, and SafeScope is not a replacement for a professional penetration
  test or code review.
- SafeScope does not look for application vulnerabilities (XSS, SQL injection,
  authentication flaws), never sends attack payloads, and will not add exploit
  modules, brute force or credential testing.
- Heuristic findings (for example guessing that a cookie is a session cookie
  from its name) carry `confidence: medium`.

## Reporting a vulnerability in SafeScope

See [SECURITY.md](../SECURITY.md).
