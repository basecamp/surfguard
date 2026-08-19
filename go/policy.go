package surfguard

//go:generate go run ./generate

import (
	"context"
	"net"
	"net/netip"
	"slices"
)

// Resolver is the DNS seam used by the resolution layer. *net.Resolver
// satisfies it; tests substitute deterministic fakes.
//
// The resolution layer queries "ip4" and "ip6" separately and never "ip",
// so an implementation must honor network: a combined lookup loses whether
// an answer came from an A or a AAAA record, and that distinction is what
// separates an ordinary IPv4 address from a hostile IPv4-mapped AAAA.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy is an immutable address policy. The zero value is the full default
// policy; there is no mutable package-level configuration.
//
// Derivation methods return adjusted copies and accumulate across calls:
//
//	fixture := surfguard.Policy{}.IANASpecialUse().AllowLoopback()
//
// Precedence, most to least binding: [Policy.Deny] > structural defenses
// (invalid, zoned, IPv4-mapped, IPv4-compatible, and NAT64 local-use
// addresses are always refused) > the [Policy.IANASpecialUse] tables >
// [Policy.AllowLoopback] and [Policy.Allow] > the default deny tables and
// the IPv6 allocated-unicast allowlist. Allow can re-admit space the default
// tables or the IPv6 allowlist would refuse; it cannot re-admit structural
// refusals or, except via AllowLoopback, space the IANASpecialUse tables
// refuse.
type Policy struct {
	specialUse bool
	loopback   bool
	allows     []netip.Prefix
	denies     []netip.Prefix
	ports      []uint16
	allPorts   bool
	redirects  int // stored as maxRedirects+1; 0 means unset (default 10)
	resolver   Resolver
}

// IANASpecialUse returns a policy that additionally blocks every prefix in
// the checked-in IANA IPv4 and IPv6 special-purpose registry snapshots,
// including globally reachable service infrastructure (AMT, AS112, the whole
// NAT64 well-known prefix). The tables also apply to NAT64/SIIT-embedded
// IPv4, so they cannot be bypassed via IPv6 encoding.
//
// Use it for advertised or discovered infrastructure values — data a remote
// peer chose. A target must never choose its own policy; trusted consumer
// code chooses it.
func (p Policy) IANASpecialUse() Policy {
	p.specialUse = true
	return p
}

// AllowLoopback returns a policy that admits 127.0.0.0/8 and ::1 on any
// port, including under IANASpecialUse. It exists so httptest fixtures (which
// bind random loopback ports) work against otherwise-strict policies. Never
// enable it outside tests and tooling that must reach operator-named local
// targets.
func (p Policy) AllowLoopback() Policy {
	p.loopback = true
	return p
}

// Allow returns a policy that admits the given prefixes where the default
// deny tables or the IPv6 allocated-unicast allowlist would refuse them.
// Allow never overrides Deny, structural defenses, or the IANASpecialUse
// tables. Invalid prefixes panic: allowing is a construction-time decision
// by trusted code, and a silently dropped allowance would fail closed in a
// way that masks the bug.
func (p Policy) Allow(prefixes ...netip.Prefix) Policy {
	p.allows = appendPrefixes(p.allows, prefixes)
	return p
}

// Deny returns a policy that refuses the given prefixes ahead of every other
// rule, including Allow and AllowLoopback. Invalid prefixes panic.
func (p Policy) Deny(prefixes ...netip.Prefix) Policy {
	p.denies = appendPrefixes(p.denies, prefixes)
	return p
}

// AllowPorts returns a policy whose connection layer admits exactly the
// given ports (accumulating with earlier calls) instead of the default
// {80, 443}. Loopback targets under AllowLoopback are exempt from port
// checks. Port 0 panics.
func (p Policy) AllowPorts(ports ...uint16) Policy {
	merged := make([]uint16, 0, len(p.ports)+len(ports))
	merged = append(merged, p.ports...)
	for _, port := range ports {
		if port == 0 {
			panic("surfguard: port 0 is not a valid allowed port")
		}
		if !slices.Contains(merged, port) {
			merged = append(merged, port)
		}
	}
	p.ports = merged
	return p
}

// AllowAllPorts returns a policy whose connection layer does not restrict
// ports. Address policy still applies.
func (p Policy) AllowAllPorts() Policy {
	p.allPorts = true
	return p
}

// MaxRedirects returns a policy whose client follows at most n redirects
// (default 10). Zero means redirects are not followed at all. Negative n
// panics.
func (p Policy) MaxRedirects(n int) Policy {
	if n < 0 {
		panic("surfguard: negative redirect limit")
	}
	p.redirects = n + 1
	return p
}

// WithResolver returns a policy whose resolution layer ([Policy.CheckURL],
// [Policy.ResolvePublicAddrs]) uses r instead of net.DefaultResolver. It is
// L2-only by design: it does not, and cannot, reconfigure the net.Dialer the
// enforcement layer builds (that field is a concrete *net.Resolver, whereas
// this seam is an interface so tests can inject fakes). The dial layer is
// unaffected regardless — it judges the literal address of every connect
// attempt no matter who resolved it, so there is no pre-check/dial gap to
// exploit. A nil r restores net.DefaultResolver.
func (p Policy) WithResolver(r Resolver) Policy {
	p.resolver = r
	return p
}

func (p Policy) maxRedirects() int {
	if p.redirects == 0 {
		return 10
	}
	return p.redirects - 1
}

func (p Policy) lookup() Resolver {
	if p.resolver != nil {
		return p.resolver
	}
	return net.DefaultResolver
}

var defaultPorts = []uint16{80, 443}

func (p Policy) portAllowed(addr netip.Addr, port uint16) bool {
	switch {
	case p.loopback && isLoopback(addr.Unmap()):
		// AllowLoopback exists for httptest fixtures on random ports.
		return true
	case p.allPorts:
		return true
	case p.ports != nil:
		return slices.Contains(p.ports, port)
	default:
		return slices.Contains(defaultPorts, port)
	}
}

// appendPrefixes clones on every derivation so sibling policies derived from
// one parent can never alias (and thereby mutate) each other's rule slices.
func appendPrefixes(dst []netip.Prefix, src []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(dst)+len(src))
	out = append(out, dst...)
	for _, prefix := range src {
		if !prefix.IsValid() {
			panic("surfguard: invalid prefix")
		}
		out = append(out, prefix.Masked())
	}
	return out
}

// Hand-transcribed from lib/surfguard.rb DISALLOWED_IPV4 (an audit test
// asserts count and membership against that constant). Ruby additionally
// consults IPAddr#private?/#loopback?/#link_local?; every range those cover
// (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16) is already present here.
var disallowedIPv4 = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"168.63.129.16/32", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

// Hand-transcribed from lib/surfguard.rb DISALLOWED_IPV6, plus the three
// ranges Ruby folds in via IPAddr#private?/#loopback?/#link_local?:
// fc00::/7 (ULA), ::1/128, fe80::/10.
var disallowedIPv6 = mustPrefixes(
	"::/128", "100::/64", "100:0:0:1::/64", "2001::/32", "2001:2::/48",
	"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fec0::/10",
	"ff00::/8",
	"::1/128", "fc00::/7", "fe80::/10",
)

var (
	// 2001::/23 is IETF special-purpose parent space: default-deny, with
	// narrow carve-outs below for the two globally reachable services.
	ietfProtocolAssignments = netip.MustParsePrefix("2001::/23")
	// AMT (2001:3::/32) and AS112-v6 (2001:4:112::/48) are globally
	// reachable service infrastructure inside the IETF parent.
	globallyReachableIETFAssignments = mustPrefixes("2001:3::/32", "2001:4:112::/48")

	// NAT64 well-known prefix: the low 32 bits are a real IPv4 target;
	// decode and re-check. The local-use variant (64:ff9b:1::/48) embeds at
	// an unrecoverable offset (RFC 6052), so it is refused whole — decoding
	// it under-blocks.
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalUse  = netip.MustParsePrefix("64:ff9b:1::/48")
	// SIIT / IPv4-translatable: decode and re-check like the NAT64 WKP.
	ipv4Translatable = netip.MustParsePrefix("::ffff:0:0:0/96")
	// IPv4-compatible ::/96 (and therefore :: and ::1) is refused outright.
	ipv4Compatible = netip.MustParsePrefix("::/96")

	loopbackIPv4 = netip.MustParsePrefix("127.0.0.0/8")
	ipv6Loopback = netip.MustParseAddr("::1")
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, cidr := range cidrs {
		prefixes[i] = netip.MustParsePrefix(cidr)
	}
	return prefixes
}

func containsAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isLoopback(addr netip.Addr) bool {
	if addr.Is4() {
		return loopbackIPv4.Contains(addr)
	}
	return addr == ipv6Loopback
}
