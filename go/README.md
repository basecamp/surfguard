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
`require`).

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
| Client | `Transport()`, `RoundTripper()`, `Client()`, `CheckRedirect(next)` | real `*http.Transport`/`*http.Client`; `Proxy: nil`; malformed request URLs refused before the transport; per-hop scheme, downgrade, host, and (via dial) address+port re-validation |

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
value there is still refused. A `WithResolver` implementation must honor the
network argument for the same reason.

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

Derivations: `Allow`/`Deny` (netip prefixes; Deny > structural defenses >
special-use tables > Allow > default tables), `AllowLoopback` (fixtures),
`AllowPorts`/`AllowAllPorts` (dial layer; default `{80, 443}`),
`MaxRedirects` (default 10), `WithResolver` (resolution seam).

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
conversion: punycode-encode before calling. No response-size limits or
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
are a minor bump with a prominent changelog entry; policy changes land in
`conformance/` and both implementations in one commit.
