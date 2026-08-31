# Surfguard for Go

Surfguard resolves, classifies, and — unlike the Ruby gem — enforces network
address policy for Go programs that fetch URLs supplied by someone else
(SSRF). The Ruby implementation at the repository root is the policy source
of truth; this module shares its IANA registry snapshots, its conformance
corpus, and its guarantees, then adds the layers that are cheap and
composable in Go: dial-time enforcement and a hardened `*http.Client`.

```go
import surfguard "github.com/basecamp/surfguard/go"
```

Go 1.23 or newer. Zero dependencies (enforced in CI: no `go.sum`, no
`require`). CI runs the suite on the 1.23 floor and on the current stable
toolchain, on Linux, macOS, and Windows.

## Installation and verification

```sh
go get github.com/basecamp/surfguard/go@vX.Y.Z
```

Releases are tagged `go/vX.Y.Z` (the Go subdirectory convention — the
version you pass to `go get` is `vX.Y.Z`) and each has a GitHub Release
whose body is the [`CHANGELOG.md`](CHANGELOG.md) entry. Both tag namespaces
in this repository are protected by the same immutable-tag ruleset, so a
released `go/` tag cannot be moved or deleted.

Integrity comes from the Go checksum database: on first fetch `go get`
verifies the module zip's hash against `sum.golang.org` and records it in
your `go.sum`, which pins it from then on. Two settings switch that
verification off for a module, and neither should match this one:
`GOSUMDB=off` disables the database outright, and a `GOPRIVATE` or
`GONOSUMDB` pattern matching `github.com/basecamp/surfguard` exempts the
module from it (`GOPRIVATE` is also the default for `GONOPROXY`, so a
matching pattern additionally bypasses the proxy and fetches straight from
VCS). There are no Sigstore attestations for the Go module — the
`gh attestation verify` recipe in the repository-root README is for the
gem's release artifact only.

## Quick start

```go
// A drop-in client: every socket connect attempt is judged by its literal
// address (DNS rebinding is caught per connection, per redirect hop, per
// Happy Eyeballs race), redirects are re-validated hop by hop, proxying is
// disabled.
client := surfguard.Client()

// Advertised or discovered infrastructure values get the stricter policy.
// A target must never choose its own policy; trusted consumer code does.
discovery := surfguard.Policy{}.IANASpecialUse().Client()

// Test fixtures: loopback admitted on any port, everything else still strict.
fixture := surfguard.Policy{}.AllowLoopback().Client()

if _, err := client.Get(userSuppliedURL); errors.Is(err, surfguard.ErrBlocked) {
    // policy refusal: deactivate the target
}
// The client surfaces DNS failures as the standard net errors (e.g.
// *net.DNSError), not ErrUnresolvable. ErrUnresolvable is an L2 signal: use
// CheckURL / ResolvePublicAddrs as a pre-flight when you need the explicit
// retry-vs-deactivate distinction before dialing.
if err := surfguard.CheckURL(ctx, userSuppliedURL); errors.Is(err, surfguard.ErrUnresolvable) {
    // lookup came back empty: retry later
}
```

## Layers

The zero value of `Policy` is the full default policy; derivation methods
return adjusted copies and accumulate.

| Layer | API | Guarantee |
|---|---|---|
| Classification | `Blocked(netip.Addr)`, `BlockedHost(string)` | pure verdicts; invalid, zoned, and malformed input fails closed; never DNS |
| Resolution | `ResolvePublicAddrs(ctx, host)`, `CheckURL(ctx, url)` | every answer judged; each address family looked up separately; legacy numeric spellings classified without DNS; malformed numeric tokens refused outright |
| Enforcement | `Control`, `ControlContext`, `DialContext` | the literal address of every connect attempt is judged at the moment of connection — no check-to-use gap; `DialContext` canonicalizes legacy-numeric literals before the resolver can see them |
| Client | `Transport()`, `RoundTripper()`, `Client()`, `CheckRedirect(next)` | real `*http.Transport`/`*http.Client`; `Proxy: nil`; malformed hosts and non-http(s) schemes refused before the transport, on the initial request and every hop; per-hop downgrade, host, and (via dial) address+port re-validation |

`DialContext` gives the numeric-host defense at dial time too: a legacy
spelling like `2130706433` or `0x7f000001` is canonicalized to its address
(`127.0.0.1`) and judged, never handed to a resolver that a wildcard answer
could hijack — so `Client().Get("http://2130706433/")` is refused exactly as
`CheckURL` would refuse it.

Names are resolved per address family — `"ip4"` and `"ip6"`, never `"ip"`. A
combined lookup loses whether an answer came from an A or a AAAA record, and
the pure-Go resolver spells an A record as its IPv4-mapped form
(`::ffff:127.0.0.1` where cgo gives `127.0.0.1`); since classification refuses
every mapped address as a hostile AAAA, a combined lookup would drop ordinary
IPv4 answers on that backend. An `ip4` answer is therefore unmapped and judged
as the IPv4 it names, while an `ip6` answer is judged as it stands, so a mapped
value there is still refused. The two queries are issued concurrently, as a
combined lookup does internally, so splitting them costs no extra round trip.

A verdict is only formed from a complete picture of the host. A family may be
missing, but only definitively — no error, or a lookup reporting that the
records do not exist. A timeout, SERVFAIL, or a context that ends
mid-resolution leaves it unknown whether that family held an address worth
refusing, so the host is reported unresolvable rather than judged on the other
family alone.

A `WithResolver` implementation must therefore honor the network argument, be
safe for concurrent use, and report an absent family as a `*net.DNSError` with
`IsNotFound` (or an empty answer with a nil error) so it is distinguishable
from a failure.

`Client()` checks the shape of every request URL — the initial one and each
redirect hop — before the transport sees it, because that is the only layer
where the evidence still exists: an `*http.Transport` dials
`req.URL.Hostname()`, which has already stripped the brackets from an
authority. Nor can this be left to `net/url`, whose IP-literal validation
tightened *after* Go 1.23, the module floor: there `url.Parse` accepts
`http://[example.com]/` and reports the host as the ordinary name
`example.com`. `Transport()` still returns a real `*http.Transport` for
callers who want to configure one, but it judges addresses rather than URL
shape — assemble a custom client from `RoundTripper()` to keep both.

`CheckRedirect(next)` runs the caller's `next` callback first; any non-nil
result it returns — including `http.ErrUseLastResponse` — stops the follow
and is returned unchanged, and only an approved (nil) redirect is validated,
so the policy always judges the request that actually goes on the wire and is
never skippable.

Bare classification and resolution do not bind a later connection: callers
using them must pin the returned addresses at connection time (keep the
hostname for Host/SNI). The enforcement layer is what closes DNS rebinding.

## Policies

The default policy blocks the documented IPv4 SSRF deny ranges — private,
loopback, link-local, CGNAT, 0/8, TEST-NETs, benchmarking, 6to4 relay,
multicast, reserved, broadcast, and the Azure WireServer address
`168.63.129.16`, which sits inside public space and is missing from every
registry-derived list. IPv6 is admitted only when inside a checked-in IANA
`Status=ALLOCATED` global unicast prefix (unallocated space is denied by
construction — deliberately not the far broader `2000::/3`), minus explicit
denies. IPv4-mapped and IPv4-compatible forms and the NAT64 local-use prefix
are refused outright; NAT64 WKP and SIIT forms decode their embedded IPv4
and re-check it.

`IANASpecialUse()` additionally blocks every prefix in the checked-in IANA
special-purpose registries — AMT, AS112, the whole NAT64 well-known prefix —
applied to transition-embedded IPv4 as well, so IPv6 encoding is not a
bypass.

### Derivations and precedence

Every derivation returns an adjusted copy; calls accumulate. Address rules
apply in this order, most to least binding:

1. Invalid and zoned addresses — refused before any rule, always.
2. `Deny(prefixes...)` — refuses ahead of every allowance, including
   `AllowLoopback`.
3. `AllowLoopback()` — admits exactly `127.0.0.0/8` and `::1`, ahead of
   everything below, **including the `IANASpecialUse()` tables**. `::1` is
   admitted even though it also sits inside the IPv4-compatible `::/96`
   prefix refused at 4 — the one structural form an allowance precedes. The
   mapped loopback `::ffff:127.0.0.1` is not in the carve-out and stays
   refused **in classification**; the dial layer unmaps before judging (the
   kernel really connects to `127.0.0.1`), so enforcement treats it as
   loopback and admits it under `AllowLoopback`, random ports included.
4. Structural transition-form refusals — IPv4-mapped and IPv4-compatible
   forms and the NAT64 local-use prefix. `Allow` never re-admits them.
5. The `IANASpecialUse()` tables.
6. `Allow(prefixes...)` — re-admits space the default deny tables or the
   IPv6 allocated-unicast allowlist would refuse. It does **not** pierce the
   special-use tables above it.
7. The default deny tables and the IPv6 allocated-unicast allowlist.

The asymmetry between `AllowLoopback` and `Allow` is the one to know about.
RFC 1918 space is in the special-purpose registry, so once a policy is built with
`IANASpecialUse()`, `Allow(netip.MustParsePrefix("10.4.0.0/16"))` does
nothing — the addresses stay blocked. An on-premises target in private space
needs a policy built without `IANASpecialUse()`; a local development target
wants `AllowLoopback()`, which admits loopback and leaves every other table in
force:

```go
surfguard.Policy{}.Allow(prefix)                   // 10.4.1.2 admitted
surfguard.Policy{}.IANASpecialUse().Allow(prefix)  // 10.4.1.2 still blocked
surfguard.Policy{}.IANASpecialUse().AllowLoopback() // 127.0.0.1 admitted, 192.31.196.7 still blocked
```

Invalid prefixes and port 0 panic: allowing is a construction-time decision
by trusted code, and a silently dropped allowance would fail closed in a way
that masks the bug.

Ports are judged only at the enforcement layer (`Control`, `DialContext`,
and therefore `Client()`); classification and resolution never see one.
The default set is `{80, 443}`, and the first `AllowPorts(ports...)` call
**replaces** it: `AllowPorts(8080)` leaves only 8080 allowed, so name 80 and
443 explicitly if they should stay. Later calls accumulate with earlier
ones. `AllowAllPorts()` removes the check. Loopback targets under
`AllowLoopback()` are exempt from the port check, so `httptest` servers on
random ports work.

`MaxRedirects(n)` caps hops the client follows (default 10; 0 follows none).
`WithResolver(r)` replaces `net.DefaultResolver` for the resolution layer
only — it does not, and cannot, reconfigure the dialer, which judges the
literal address of every connect attempt no matter who resolved it.

## Refused vs unresolvable

| Condition | Error | `errors.Is` |
|---|---|---|
| blocked address, malformed host, refused port/network/scheme/redirect | `*Violation` | `ErrBlocked` |
| empty, oversized, or invalid resolver answer; resolver failure | `*UnresolvableError` | `ErrUnresolvable` |

The two families are deliberately unrelated: blocked means deactivate the
target, unresolvable means retry later. Both survive the `url.Error` /
`net.OpError` wrapping of `net/http`, so `errors.Is(err, surfguard.ErrBlocked)`
works on the error a real `client.Do` returns.

The fixed, non-leaking message is a property of the surfguard error itself:
`(*Violation).Error()` and `(*UnresolvableError).Error()` never contain the
host, address, or port. The wrappers `net/http` adds do leak — a `*url.Error`
prints the request URL and a dial-time `*net.OpError` prints the remote
address. Code that must not disclose the target should classify with
`errors.Is`/`errors.As` and log the extracted `*Violation`, not the outer
error's text.

A `*Violation` carries the gate that refused and, when known, what it
refused. `Reason.String()` is a fixed token suitable for a structured log
field; it never echoes input.

The classification layer (`Blocked`, `BlockedHost`) returns booleans and
never produces a `Violation`; the reasons below come from the resolution,
enforcement, and client layers.

| `Reason` | `String()` | Produced by |
|---|---|---|
| `ReasonBlockedAddr` | `blocked-address` | `CheckURL` when any answer or literal is refused; `Control`/`DialContext` when a connect attempt's address is refused; `CheckRedirect` when a redirect hop's literal host is refused. `ResolvePublicAddrs` never constructs one — it filters refused answers, so an all-blocked host comes back as an **empty slice with a nil error**, and callers must treat empty as a refusal |
| `ReasonMalformedHost` | `malformed-host` | `CheckURL`/`ResolvePublicAddrs`, `DialContext`, `RoundTripper`/`Client`, and `CheckRedirect` for a host that is not a well-formed name or literal — a bracketed name, a malformed numeric token, a non-ASCII name. A directly invoked `RoundTripper` also refuses a nil request this way; `Client().Do(nil)` never reaches the wrapper — `net/http` itself fails first |
| `ReasonNetwork` | `network` | `DialContext` for anything but `tcp`/`tcp4`/`tcp6`; `Control` for anything but the concrete `tcp4`/`tcp6` attempt |
| `ReasonPort` | `port` | `Control`/`DialContext` for a port outside the policy's allowed set |
| `ReasonScheme` | `scheme` | `RoundTripper`/`Client` and `CheckRedirect` for a scheme other than `http` or `https`. `CheckURL` judges addresses only and does **not** validate the scheme — a successful preflight of an `ftp://` URL proves nothing about it |
| `ReasonRedirectDowngrade` | `redirect-downgrade` | `CheckRedirect` for an `https` → `http` hop |
| `ReasonTooManyRedirects` | `too-many-redirects` | `CheckRedirect` when the `MaxRedirects` cap is exceeded |

Fields: `Host` (the host string, when the refusal was host-level), `Addr`
(the refused `netip.Addr`, when address-level), `Port` (when
connection-level), `Reason`. An `*UnresolvableError` carries `Host` and
`Err`, the underlying resolver error — reachable through the field and
`errors.Is`/`errors.As`, never through the message, because resolver errors
embed attacker-controlled detail. A resolver error that itself matches
`ErrBlocked` is deliberately left out of the unwrap chain so one error can
never match both families.

`ErrUnresolvable` is produced only by the resolution layer. `Client()`
delegates DNS to `net.Dialer`, so a lookup failure on a client request
surfaces as the standard `*net.DNSError` inside the `*url.Error`, not as
`ErrUnresolvable`. Use `CheckURL` as a preflight when you need the explicit
retry-versus-deactivate distinction, and classify the client's own errors by
family:

```go
// Preflight: the explicit retry-versus-deactivate distinction.
if err := surfguard.CheckURL(ctx, userSuppliedURL); err != nil {
    var v *surfguard.Violation
    switch {
    case errors.As(err, &v):
        log.Printf("refused reason=%s", v.Reason) // fixed token, no target detail
        // deactivate the target
    case errors.Is(err, surfguard.ErrUnresolvable):
        // retry later
    }
    return
}

// The request itself: every hop and every connect attempt is still judged.
resp, err := client.Get(userSuppliedURL)
if err == nil {
    defer resp.Body.Close()
}
var v *surfguard.Violation
var dnsErr *net.DNSError
switch {
case errors.As(err, &v):
    log.Printf("refused reason=%s", v.Reason) // rebinding, redirect, or port refusal
    // deactivate the target
case errors.As(err, &dnsErr):
    // lookup failed at dial time; retry later
case err != nil:
    // transport or HTTP error — the net/http wrappers include the URL
}
```

## Ruby parity and divergences

The shared corpus under `../conformance` asserts identical classification
verdicts in both implementations. Deliberate divergences:

| | Ruby | Go |
|---|---|---|
| Malformed host in resolution | silent `[]` | `*Violation` (`ReasonMalformedHost`) — Go callers check errors |
| Legacy numeric parsing | platform `getaddrinfo(AI_NUMERICHOST)` | own `inet_aton` grammar: identical on every platform, leading zeros always octal |
| `BlockedHost` on a legacy spelling (`"2130706433"`) | `blocked_address?` fails closed (not an `IPAddr`) | classified authoritatively, consistent with resolution |
| Mapped IPv4 (`::ffff:a.b.c.d`) | blocked in classification | blocked in classification; the dial layer unmaps and judges the embedded IPv4, because that is what the kernel connects to |
| Enforcement / HTTP layers | out of scope by design (caller pins) | `Control`/`DialContext`/`Client` provided |
| Adversarial-object hardening (`bind_call`) | required | moot under Go's type system |

## Not provided

No proxy support: `Transport()` sets `Proxy: nil` because a proxied request
would have the proxy's address judged instead of the target's. No IDN
conversion: punycode-encode before calling — a non-ASCII host is refused as
malformed rather than folded, because `http.Transport` IDNA-normalizes one
before dialing (`ⓛocalhost` becomes `localhost`) and the host judged would not
be the host dialed. No response-size limits or
request deadlines beyond the client's 30s timeout: those remain caller
policy.

## Registry data and releases

The module is self-contained: it reads its shared data from
`testdata/conformance` and `testdata/iana`, checked-in mirrors of the
repo-root `conformance/` corpus and `script/iana/` snapshots (the same
snapshots the Ruby constants are generated from). A drift test asserts the
mirrors are byte-identical to those sources when the full repo is present,
and the policy tables are generated (`go generate`) from `testdata/iana` with
a CI staleness check — so nothing falls out of sync, and `go test ./...`
passes against a downloaded module zip that contains only files beneath
`go/`.

Module tags follow the Go subdirectory convention: `go/vX.Y.Z`. New denies
are a minor bump with a prominent entry in [`CHANGELOG.md`](CHANGELOG.md),
which is also the body of the tag's GitHub Release; policy changes land in
`conformance/` and both implementations in one commit.

## Security

Surfguard is a security control, so a classification bug — an address in a
blocked range judged public, an encoding or transition form that reaches a
blocked address, a parser or resolver discrepancy that connects somewhere
other than what was classified — is a vulnerability, not an ordinary defect.
Report it privately through the
[security policy](https://github.com/basecamp/surfguard/security/policy).
Do not open a public issue.
