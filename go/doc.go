// Package surfguard resolves and classifies network addresses so that code
// fetching user-supplied URLs cannot be steered into internal, metadata, or
// otherwise non-public endpoints (SSRF).
//
// The package is layered; use the highest layer that fits:
//
//   - Classification: [Policy.Blocked], [Policy.BlockedHost] judge a single
//     address or host string. Pure, no I/O.
//   - Resolution: [Policy.ResolvePublicAddrs], [Policy.CheckURL] resolve a
//     host and judge every answer. Legacy numeric spellings (0x7f000001,
//     2130706433, 127.1) are classified authoritatively and never sent to
//     DNS; malformed numeric-shaped tokens are refused outright.
//   - Enforcement: [Policy.Control], [Policy.ControlContext],
//     [Policy.DialContext] judge the literal address of every socket connect
//     attempt. This is the layer that defeats DNS rebinding: the address
//     checked is the address connected, with no time-of-check gap, on every
//     redirect hop, Happy Eyeballs race, and connection-pool miss.
//   - Client: [Policy.Client] and [Policy.Transport] return real
//     *http.Client / *http.Transport values wired to the enforcement layer,
//     with proxying disabled and redirects re-validated per hop.
//
// The zero value of [Policy] is the full default policy. Derivation methods
// ([Policy.IANASpecialUse], [Policy.AllowLoopback], [Policy.Allow],
// [Policy.Deny], ...) return adjusted copies; calls accumulate.
//
// # Policies
//
// The default policy blocks private, loopback, link-local, CGNAT, metadata,
// benchmarking, documentation, multicast, and reserved IPv4 space (including
// the Azure WireServer address 168.63.129.16, which sits inside public
// space); on IPv6 it additionally requires membership in the IANA-allocated
// global unicast ranges, so unallocated IPv6 space is denied by construction.
// IPv4 addresses embedded in NAT64/SIIT transition prefixes are decoded and
// re-checked; IPv4-mapped and IPv4-compatible forms and the NAT64 local-use
// prefix are refused outright.
//
// [Policy.IANASpecialUse] additionally blocks every prefix in the checked-in
// IANA special-purpose registry snapshots, including globally reachable
// service infrastructure (AMT, AS112, the whole NAT64 well-known prefix) —
// applied to transition-embedded IPv4 as well, so it cannot be bypassed via
// IPv6 encoding. Use it for advertised or discovered infrastructure values.
// A target must never choose its own policy; trusted consumer code chooses
// it.
//
// Policy tables are generated from the IANA registry snapshots checked in
// under script/iana in the surfguard repository, shared byte-for-byte with
// the Ruby implementation and verified by a shared conformance corpus.
//
// # What surfguard does not do
//
// DNS rebinding is only defeated at the enforcement layer: callers using
// bare classification or resolution must pin the returned addresses at
// connection time. There is no proxy support ([Policy.Transport] sets Proxy
// to nil deliberately: a proxied request would have the proxy's address
// validated instead of the target's). International domain names are not
// converted; punycode-encode before calling.
package surfguard
