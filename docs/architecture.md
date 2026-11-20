# Architecture

SafeScope is a small pipeline. Every entry point (CLI, web API, Python API,
GitHub Action) ends up in the same `Scanner.scan()` call.

```text
CLI (cli.py) ─┐
Web API (web.py, api/scan.py) ─┼─► normalize_target ─► ScanContext ─► Scanner ─► score() ─► reporter
Python API (safescope.scan) ─┘                         (cache, guard)   (checks)              (console, json,
                                                                                               markdown, html, sarif)
```

## Modules

| Module | Responsibility | Talks to the network? |
|---|---|---|
| `models.py` | `Severity`, `Status`, `Confidence`, `Finding`, `ScanResult` (+ JSON round trip) | no |
| `http.py` | Minimal HTTP client: manual redirects, body cap, time budget, optional guard + DNS pinning | yes |
| `tls.py` | TLS handshake, certificate details, legacy protocol probe | yes |
| `netguard.py` | SSRF guard: resolve once, refuse non-public answers, return the address to pin | DNS only |
| `context.py` | `ScanContext`: target normalisation, per-scan cache, insecure fallback for bad certificates | through `HttpClient` |
| `checks/*.py` | One class per check family; `run()` fetches through the context, `analyze()` judges | through the context |
| `scoring.py` | 0–100 score and A+…F grade with caps for high/critical findings | no |
| `scanner.py` | Runs the checks, isolates crashes, builds the `ScanResult` | through the context |
| `reporters/*.py` | Turn a `ScanResult` into text (one function per format) | no |
| `cli.py` | `scan`, `report`, `checks`, `serve` commands, multi-target concurrency, exit codes | indirectly |
| `web.py` | Routing, validation, rate limiting, concurrency slots, security headers | indirectly |
| `api/scan.py` | Vercel entry point; maps rewritten paths to `web.handle_request` | indirectly |

## Design rules

1. **Checks never open sockets.** They ask `ScanContext`, which fetches each URL
   once per scan and caches errors too. Five checks needing the home page cost
   one request.
2. **I/O and judgement are separate.** `run()` collects data and turns network
   errors into `error` findings; `analyze()` is a pure function that tests call
   directly.
3. **Everything risky is injected.** The HTTP client, its guard and the TLS
   inspector are parameters, so tests replace them and the web app adds the
   SSRF guard without the checks knowing.
4. **One crash never hides the rest.** The scanner wraps every check; an
   exception becomes a `<check>.crash` finding.
5. **No silent passes.** A test that could not run is `skipped`, never `pass`.

## Lifecycle of one scan

1. The entry point builds an `HttpClient` (timeout, optional guard, optional
   total budget) and a `Scanner`.
2. `ScanContext` normalises the target (`example.com` → `https://example.com/`)
   and rejects malformed input.
3. For each check, `check.run(ctx)` asks the context for responses:
   `main_response()`, `fetch(url)`, `fetch_path(path)` or `tls_info()`.
4. When a guard is set, every connection — each redirect hop and the TLS
   handshake — is validated and pinned to the validated address.
5. If the certificate is untrusted, the context refetches without verification
   (still guarded) so header and cookie checks can run; the `tls` check reports
   the certificate problem.
6. `score()` turns the findings into a score and grade.
7. A reporter renders the `ScanResult`.

## Adding things

- A check: see [writing-checks.md](writing-checks.md) and add its IDs to
  [checks.md](checks.md) (a test enforces it).
- An output format: a function `(ScanResult) -> str` in `reporters/` plus one
  line in `REPORTERS`; the CLI picks it up automatically.
