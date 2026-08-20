package surfguard

import "net/netip"

// Blocked reports whether addr must be refused under the policy. Invalid and
// zoned addresses fail closed. This is the classification core every other
// layer delegates to.
//
// IPv4-mapped input (::ffff:a.b.c.d) is blocked outright: a mapped address
// in classification input is a hostile AAAA record or a caller bug, never a
// legitimate public target. (The dial layer unmaps before judging instead,
// because there the kernel really is about to connect to the embedded IPv4.)
func (p Policy) Blocked(addr netip.Addr) bool {
	switch {
	case !addr.IsValid() || addr.Zone() != "":
		return true
	case containsAny(p.denies, addr):
		return true
	case p.loopback && isLoopback(addr):
		return false
	case addr.Is4():
		return p.blockedIPv4(addr)
	default:
		return p.blockedIPv6(addr)
	}
}

// blockedIPv4 judges a plain IPv4 address; it is also the re-check applied
// to the low 32 bits decoded from NAT64/SIIT transition prefixes, so user
// denies and the strict tables apply to embedded IPv4 too.
func (p Policy) blockedIPv4(addr netip.Addr) bool {
	switch {
	case containsAny(p.denies, addr):
		return true
	case p.specialUse && containsAny(ianaSpecialUseIPv4, addr):
		return true
	case containsAny(p.allows, addr):
		return false
	default:
		return containsAny(disallowedIPv4, addr)
	}
}

// blockedIPv6 mirrors the Ruby pipeline exactly: strict special-use tables
// first (so the whole NAT64 WKP registration wins before its decode), then
// the structural transition-form refusals, then the embedded-IPv4 decode,
// then deny tables, and finally membership in the IANA-allocated global
// unicast ranges — an allowlist, so unallocated IPv6 space is denied by
// construction.
func (p Policy) blockedIPv6(addr netip.Addr) bool {
	switch {
	case p.specialUse && containsAny(ianaSpecialUseIPv6, addr):
		return true
	case addr.Is4In6():
		return true
	case ipv4Compatible.Contains(addr):
		return true
	case nat64LocalUse.Contains(addr):
		return true
	case nat64WellKnown.Contains(addr) || ipv4Translatable.Contains(addr):
		return p.blockedIPv4(embeddedIPv4(addr))
	case containsAny(p.allows, addr):
		return false
	case containsAny(globallyReachableIETFAssignments, addr):
		return false
	case ietfProtocolAssignments.Contains(addr):
		return true
	case containsAny(disallowedIPv6, addr):
		return true
	default:
		return !containsAny(ianaAllocatedIPv6Unicast, addr)
	}
}

func embeddedIPv4(addr netip.Addr) netip.Addr {
	raw := addr.As16()
	return netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
}

// Blocked reports whether addr must be refused under the default policy.
func Blocked(addr netip.Addr) bool { return Policy{}.Blocked(addr) }
