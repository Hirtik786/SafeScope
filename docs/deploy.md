# Deploying the SafeScope web app

The web app is pure Python with no dependencies, so it runs on any free host that supports
Python.

## Vercel (recommended, free)

1. Push the repository to GitHub (already done if you are reading this there).
2. Open <https://vercel.com/new>, sign in with GitHub and **Import** `SafeScope`.
3. Keep all defaults (Framework preset: *Other*) and click **Deploy**.
4. Open `https://<your-project>.vercel.app/api/health`; it should answer `{"status":"ok"}`.

How it works: `vercel.json` sends every request to the single Python function
`api/scan.py`, which calls `safescope.web.handle_request`. That is the same code that
`safescope serve` runs locally, so local tests cover production behaviour.

Every push to `main` redeploys automatically, and pull requests get preview URLs.

Notes:

- The free (Hobby) plan is for non-commercial use.
- The rate limiter and the 4-scan concurrency limit are in memory, so each
  serverless instance counts on its own. For strict global limits, put a shared
  store such as Redis behind `RateLimiter`.

## Any other host (Render, Railway, Fly.io, a VPS)

Run the built-in server behind the platform's HTTPS proxy:

```bash
pip install git+https://github.com/Karim-Bazooka/SafeScope.git
safescope serve --host 0.0.0.0 --port $PORT
```

On a VPS, put nginx or Caddy in front of it to terminate TLS.

## Security model

The full description lives in [security-model.md](security-model.md). In short:
every connection, each redirect hop and the TLS handshake are validated by
`safescope.netguard` and pinned to the validated address (DNS rebinding safe);
the service allows web ports only, limits time, concurrency and request rate,
and never returns resolved addresses in error messages.

### Client IP behind other hosts

`api/scan.py` trusts `X-Forwarded-For` because Vercel overwrites it. On any
other host, run `safescope serve` without `--trust-proxy` (rate limits then use
the TCP peer address), or add `--trust-proxy` only behind a proxy that
overwrites the header.
