# Changelog — Surfguard for Rust

The crate at `rust/` versions independently of the gem and the Go module. This
file is the human-readable record for `rust/vX.Y.Z` tags; the gem's record is
its per-release `RELEASE_NOTES_X.Y.Z.md`, and the Go module's is
`../go/CHANGELOG.md`. Neither version number ever applies to this crate.

**A new deny is a minor version bump with its own entry under a "Policy" heading
below.** That is the promise `README.md` and `../conformance/README.md` make to
consumers: a policy change can turn a host that resolved yesterday into a
refusal today, and the entry is where a consumer finds out which one and why.
Policy changes land in `conformance/` and in every implementation in the same
commit, so the entry names the corpus case as well as the range.

## v0.1.0 — unreleased

First release of the Rust implementation. Rust 1.91 or newer, edition 2024,
zero dependencies, `#![forbid(unsafe_code)]`.

**Policy.** No change. `Policy::Default` and `Policy::IanaSpecialUse` are the
gem's `:default` and `:iana_special_use` of the same commit (gem 0.2.0),
generated from the same checked-in IANA snapshots under `script/iana/` and
asserted against the shared corpus in `conformance/`.

**Added.**

- `resolve_public_ips`, `resolvable_public_ip`, `enforce_public_ip`,
  `resolve_public_ip`: the gem's plural, predicate, enforcement, and single
  APIs, with its contract for malformed input, unresolvable lookups, and mixed
  answers; IPv4-first ordering, in-order deduplication, and the 256-answer
  limit.
- `Policy::blocks` and `blocked_address`: the classifier, for an `IpAddr` and
  for a string as Ruby's `IPAddr` reads one.
- `Resolver` and `SystemResolver`: the injectable lookup, and `getaddrinfo`.
- `Classifier`: a `Policy`, or a closure that wraps one with a consumer's own
  exception.
- `Violation`, `Unresolvable`, and `Error`, with the gem's fixed messages.

**Divergences from the gem**, deliberate and documented in `README.md`: an
unknown policy does not compile; legacy numeric hosts are read with glibc's
grammar on every platform; the default resolver is `getaddrinfo` rather than
`Resolv`; a `mailto://` URL with no query is malformed where the gem lets
`URI::InvalidComponentError` escape.

**Not provided.** No HTTP client, dial-time enforcement, redirect handling, or
IDN conversion.
