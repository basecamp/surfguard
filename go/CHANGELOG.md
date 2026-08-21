# Changelog — Surfguard for Go

The Go module at `go/` versions independently of the gem. This file is the
human-readable record for `go/vX.Y.Z` tags; the gem's record is its per-release
`RELEASE_NOTES_X.Y.Z.md` and GitHub Release. A gem version number never applies
to this module, and this file never describes gem changes.

**A new deny is a minor version bump with its own entry under a "Policy" heading
below.** That is the promise `README.md` and `../conformance/README.md` make to
consumers, and it is what makes an upgrade reviewable: a policy change can turn
a host that resolved yesterday into `ErrBlocked` today, and the entry is where a
consumer finds out which one and why. Policy changes land in `conformance/` and
in both implementations in the same commit, so the entry names the corpus case
as well as the range.

Each released tag also gets a GitHub Release whose body is the entry below, so
the record is readable without a checkout — see `../RELEASING.md`.

## v0.1.0 — 2026-08-19

First release of the Go implementation. `github.com/basecamp/surfguard/go`,
Go 1.23 or newer, zero dependencies (enforced in CI: no `go.sum`, no `require`).

**Policy.** No change. The default policy and `IANASpecialUse()` are the Ruby
policy of the same commit, generated from the same checked-in IANA snapshots
under `script/iana/` and asserted against the shared corpus in `conformance/`.
There is no prior Go release for a range to have been added to.

**Added.**

- Classification — `Blocked(netip.Addr)`, `BlockedHost(string)`. Pure verdicts;
  invalid, zoned, and malformed input fails closed; never resolves.
- Resolution — `ResolvePublicAddrs(ctx, host)`, `CheckURL(ctx, url)`. Every
  answer judged, each address family looked up separately, legacy numeric
  spellings classified without DNS.
- Enforcement — `Control`, `ControlContext`, `DialContext`. The literal address
  of every connect attempt is judged at the moment of connection, so there is no
  check-to-use gap; legacy-numeric literals are canonicalized before the
  resolver can see them.
- Client — `Transport()`, `RoundTripper()`, `Client()`, `CheckRedirect(next)`.
  Real `net/http` types, `Proxy: nil`, malformed hosts and non-http(s) schemes
  refused before the transport on the initial request and every hop.
- Derivations — `Allow`, `Deny`, `AllowLoopback`, `AllowPorts`, `AllowAllPorts`,
  `MaxRedirects`, `WithResolver`, `IANASpecialUse`.
- Errors — `ErrBlocked` (`*Violation`) means deactivate the target;
  `ErrUnresolvable` (`*UnresolvableError`) means retry later. The two are
  deliberately unrelated and both survive `net/http`'s `url.Error`/`net.OpError`
  wrapping.

**Divergences from the gem**, deliberate and documented in `README.md`: a
malformed host in resolution is a `*Violation` rather than a silent empty
result; legacy numeric parsing uses the module's own `inet_aton` grammar rather
than the platform resolver; `BlockedHost` classifies a legacy spelling
authoritatively; the dial layer unmaps IPv4-mapped addresses and judges the
embedded IPv4, because that is what the kernel connects to.

**Not provided.** No proxy support, no IDN conversion, no response-size limits,
and no request deadlines beyond the client's 30s timeout.
