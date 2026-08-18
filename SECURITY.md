# Security Policy

Surfguard is a security control — an SSRF address guard — so classification bugs are security
vulnerabilities, not ordinary defects. Please report them privately.

## Reporting a vulnerability

Report privately via GitHub's vulnerability reporting:
[**Report a vulnerability**](https://github.com/basecamp/surfguard/security/advisories/new)
(the repo's **Security** tab → **Report a vulnerability**).

Open-source reports aren't bounty-eligible, but we also accept them via
[hackerone.com/basecamp](https://hackerone.com/basecamp) if you'd like the report on your
HackerOne record — see the
[37signals security response policy](https://37signals.com/policies/security/response/).

**Do not open a public issue for security bugs.**

## What qualifies

Anything that lets a blocked address through, for example:

- An address in a blocked range that Surfguard classifies as public.
- A resolution path (encoding, embedding, transition mechanism) that reaches a blocked address
  despite validation.
- A parser or resolver discrepancy that lets a caller following a documented API contract connect
  to a different address than Surfguard classified.

Surfguard does not perform the fetch itself. Scheme restrictions, redirect handling, connection
pinning, custom DNS64 prefixes, and nonstandard NSS sources have caller or deployment requirements
documented in the README. Those boundaries by themselves are not classification bugs, but a bypass
when the documented contract is followed qualifies.

Synchronous name resolution has no independent cancellation deadline; callers own request and
worker deadlines. Public-addressed internal routes, custom DNS64, ISATAP/6rd, provider aliases,
proxy configuration, and resolver/NSS divergence remain deployment risks requiring egress controls.

Non-security bugs and questions belong in the
[regular issue tracker](https://github.com/basecamp/surfguard/issues).

## Supported versions

The latest released version. Fixes ship as a new release, not backports.

## What to expect

We'll acknowledge your report, work with you on a fix, and coordinate disclosure through a
GitHub Security Advisory. Reporters are credited in the advisory unless they prefer otherwise.
