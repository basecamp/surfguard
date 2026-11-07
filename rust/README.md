# Surfguard for Rust

Surfguard resolves and classifies addresses for Rust programs that fetch a URL
supplied by someone else (SSRF). Like the Ruby gem at the repository root,
which is the policy source of truth, it is deliberately not an HTTP client:
the caller owns scheme restrictions, redirects, connection pinning, response
limits, retries, and request deadlines. It shares the gem's IANA registry
snapshots, its conformance corpus, its guarantees, and its API.

```toml
[dependencies]
surfguard = { git = "https://github.com/basecamp/surfguard", tag = "rust/vX.Y.Z" }
```

Rust 1.91 or newer, edition 2024. Zero dependencies (enforced in CI: the
lockfile holds only this workspace) and `#![forbid(unsafe_code)]`. CI runs
the suite on the 1.91 floor and on the current stable toolchain, on Linux,
macOS, and Windows.

## APIs and policies

| Gem | Crate |
|---|---|
| `resolve_public_ips(host, policy:)` | `resolve_public_ips(host, &policy, &resolver) -> Result<Vec<IpAddr>, Unresolvable>` |
| `resolvable_public_ip?(url, policy:)` | `resolvable_public_ip(url, &policy, &resolver) -> bool` |
| `enforce_public_ip(url, policy:)` | `enforce_public_ip(url, &policy, &resolver) -> Result<(), Error>` |
| `resolve_public_ip(url, policy:)` | `resolve_public_ip(url, &policy, &resolver) -> Result<Option<IpAddr>, Unresolvable>` |
| `blocked_address?(ip, policy:)` | `Policy::blocks(IpAddr)`, or `blocked_address(&str, Policy)` for a string |
| `:default`, `:iana_special_use` | `Policy::Default`, `Policy::IanaSpecialUse` |
| `Violation`, `Unresolvable` | `Violation::{Blocked, Malformed}`, `Unresolvable`, and `Error` holding either |

The policies, the contract for each condition, the fixed messages, IPv4-first
ordering, deduplication, and the 256-answer limit are the gem's, as the
[repository README](../README.md#apis-and-policies) describes them:

| Condition | plural | predicate | enforce | single | classifier |
|---|---|---|---|---|---|
| malformed direct input | `Ok([])` | `false` | `Violation::Malformed` | `Ok(None)` | `true` |
| empty, failed, or oversized resolver result | `Unresolvable` | `false` | `Unresolvable` | `Unresolvable` | n/a |
| mixed public and blocked answers | public subset | `false` | `Violation::Blocked` | `Ok(None)` | n/a |

```rust
use surfguard::{Policy, SystemResolver};

match surfguard::resolve_public_ips(host, &Policy::Default, &SystemResolver) {
    Ok(addresses) if addresses.is_empty() => { /* refused: deactivate the target */ }
    Ok(addresses) => { /* pin a connection to one of these, keeping the host for SNI */ }
    Err(surfguard::Unresolvable) => { /* retry later */ }
}
```

Only a returned address can be pinned. The predicate and enforcement helpers
are conservative preflights that bind no later connection.

## Resolvers

A `Resolver` looks a name up; it is asked only for names, never for an address
literal or a legacy numeric spelling. `SystemResolver` is the platform's
`getaddrinfo`, and any `Fn(&str) -> io::Result<Vec<IpAddr>>` is a resolver too,
which is how tests answer without a network.

Resolution blocks the calling thread and has no deadline of its own, as the
gem's does not. The caller applies a deadline around the whole operation. An
async program runs it where blocking is allowed, as `tokio::net::lookup_host`
runs `getaddrinfo` itself:

```rust
let admitted = tokio::task::spawn_blocking(move || {
    surfguard::resolve_public_ips(&host, &Policy::Default, &SystemResolver)
})
.await?;
```

## Classifiers

The resolution APIs judge each answer with a `Classifier`. `Policy` is one,
and so is any `Fn(IpAddr) -> bool`, so a consumer can wrap a policy with an
exception of its own, such as a test fixture on loopback that trusted
configuration turns on:

```rust
let fixture = |address: IpAddr| !address.is_loopback() && Policy::Default.blocks(address);
surfguard::resolve_public_ips(host, &fixture, &SystemResolver)
```

Trusted code chooses the classifier, never the target.

## Ruby parity and divergences

The shared corpus under `../conformance` asserts identical verdicts in every
implementation, and CI replays the gem's own verdicts for tens of thousands of
addresses, host spellings, and URLs, table edges and random spellings among
them, against this crate (`tests/ruby/verdicts.rb`, `tests/ruby_parity.rs`).
Deliberate divergences:

| | Ruby | Rust |
|---|---|---|
| Unknown policy | `ArgumentError` at run time | an enum: does not compile |
| Input types and adversarial-object hardening | `String` or `IPAddr`, copied through owned implementations | `&str` and `IpAddr`: moot |
| Legacy numeric parsing | the platform's `getaddrinfo(AI_NUMERICHOST)` | glibc's grammar (`inet_aton_exact`, `inet_pton`) on every platform, the one production runs |
| Default resolver | `Resolv.getaddresses`: the hosts file and DNS | `getaddrinfo`: whatever the name service switch consults, in its order |
| Returned addresses | frozen strings | `IpAddr` |
| `mailto://host` with no query | `URI::InvalidComponentError` escapes | malformed |

URLs are read with Ruby's `URI.parse` grammar, RFC 3986 and the checks its
scheme classes add, not the WHATWG grammar most Rust URL crates follow: a
non-ASCII or percent-encoded host is malformed rather than converted.

## Not provided

No HTTP client, dial-time enforcement, or redirect handling: the Go module
offers those because they are cheap and idiomatic there; here, pin the
returned address in the client you already have. No IDN conversion:
punycode-encode a host before calling.

## Registry data and releases

The crate is self-contained: it reads its shared data from `testdata/conformance`
and `testdata/iana`, checked-in mirrors of the repository's `conformance/` corpus
and `script/iana/` snapshots. A drift test asserts the mirrors are byte-identical
to those sources when the whole repository is present. The policy tables in
`src/iana.rs` are generated from `testdata/iana` and checked for staleness in CI:

```sh
cargo run -p surfguard-generate              # rewrite src/iana.rs
cargo run -p surfguard-generate -- --check   # fail if it is stale
```

Each table entry is a CIDR string parsed at compile time, so a malformed entry
fails the build.

Releases are tagged `rust/vX.Y.Z` and versioned independently of the gem and
the Go module. A new deny is a minor bump with a prominent entry in
[`CHANGELOG.md`](CHANGELOG.md); policy changes land in `conformance/` and every
implementation in one commit.

## Security

A classification bug is a vulnerability, not an ordinary defect. Report it
privately through the
[security policy](https://github.com/basecamp/surfguard/security/policy). Do not
open a public issue.
