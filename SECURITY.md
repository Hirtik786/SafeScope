# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | ✅ |
| 0.1.x | ❌ (upgrade: 0.2.0 fixes a DNS rebinding bypass in the web service) |

## Reporting a vulnerability

Please **do not open a public issue** for security problems in SafeScope itself.

Use GitHub's private reporting instead:
**[Report a vulnerability](https://github.com/Karim-Bazooka/SafeScope/security/advisories/new)**

Please include steps to reproduce and the impact you expect. You can expect an
acknowledgement within 72 hours and a fix or mitigation plan within 14 days for
confirmed issues. Reporters are credited in the release notes unless they prefer otherwise.

## Scope

In scope: bugs in SafeScope that could harm its users — for example HTML/script injection in
generated reports, unsafe handling of server responses, or the scanner sending requests that are
not passive.

Out of scope: findings SafeScope reports about third-party websites. Contact those site owners
directly (ideally via their `security.txt`).

## How SafeScope protects itself

The threat model, SSRF/DNS-rebinding protection and service limits are described
in [docs/security-model.md](docs/security-model.md).

## Responsible use

SafeScope is designed for checking systems you own or are authorised to test. Do not use it
against systems without permission.
