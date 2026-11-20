# Acceptable use

SafeScope only makes requests a normal browser would make, but scanning still
means probing someone's server. These rules apply to the command line tool,
the GitHub Action and the public web service.

1. **Scan only targets you own or have explicit permission to test.** For a
   client or employer, get that permission in writing.
2. **Do not publish results about a third party's site** without their
   consent. If you find a problem on someone else's site, report it privately,
   ideally through the contact in their `/.well-known/security.txt`.
3. **Do not try to bypass the public service's limits** (rate limits, SSRF
   protection, port restrictions). Run SafeScope locally instead; there are no
   limits there.
4. **Do not use SafeScope as part of an attack**, or to map networks you are
   not authorised to assess.

The public instance at <https://safescope-one.vercel.app> is provided as is,
without guarantees of availability or accuracy, and may block abusive clients.
Results are indicators, not proof that a site is secure.

Found a vulnerability in SafeScope itself? See [SECURITY.md](../SECURITY.md).
