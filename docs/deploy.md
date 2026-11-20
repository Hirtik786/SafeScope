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
- The rate limiter is in memory, so each serverless instance counts on its own. For heavy
  traffic, put a shared store such as Vercel KV or Upstash Redis behind `RateLimiter`.

## Any other host (Render, Railway, Fly.io, a VPS)

Run the built-in server behind the platform's HTTPS proxy:

```bash
pip install git+https://github.com/Karim-Bazooka/SafeScope.git
safescope serve --host 0.0.0.0 --port $PORT
```

On a VPS, put nginx or Caddy in front of it to terminate TLS.

## Security model

- Only `GET` requests are made to scanned sites, with a 6 second timeout per connection.
- `safescope.netguard.assert_public_url` runs before every connection, including redirects
  and the TLS handshake. It resolves the host and refuses private, loopback, link-local,
  carrier-grade NAT, multicast and reserved addresses, plus non-web ports.
- Known limitation: a DNS record could change between the guard's lookup and the connection
  (DNS rebinding). The window is milliseconds and the scanner only reads response headers,
  but pinning the resolved IP is on the roadmap.
