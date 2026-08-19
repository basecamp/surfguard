package surfguard

import (
	"net/netip"
	"strconv"
	"strings"
)

// The numeric-host defense: legacy inet_aton spellings (2130706433,
// 0x7f000001, 127.1, 0177.0.0.1) denote real IPv4 addresses to connection
// parsers, so they must be classified authoritatively and never sent to DNS
// — a wildcard or search domain would otherwise answer for them and launder
// an internal target through a public-looking A record. Malformed
// numeric-shaped tokens (trailing dots, doubled separators, zone or prefix
// decorations) are refused outright, before any parser could normalize them.
//
// Unlike the Ruby implementation, which delegates legacy parsing to the
// platform's getaddrinfo(AI_NUMERICHOST), this parser implements the
// inet_aton grammar itself: identical classification on every platform, with
// leading-zero components always read as octal (the BSD/glibc behavior).

type hostKind int

const (
	hostMalformed hostKind = iota
	hostLiteral
	hostName
)

// classifyHost decides, without any DNS or platform parser, whether host is
// an address literal (returned), a legitimate hostname (to be resolved), or
// malformed (refused). Precondition: host passed normalizeHost.
func classifyHost(host string) (hostKind, netip.Addr) {
	if strings.Contains(host, ":") {
		// A colon means an IPv6 literal or nothing: never DNS.
		return classifyIPv6Literal(host)
	}
	switch {
	case !validHostSyntax(host):
		return hostMalformed, netip.Addr{}
	case malformedNumericCandidate(host):
		return hostMalformed, netip.Addr{}
	}
	if addr, ok := parseLegacyIPv4(host); ok {
		return hostLiteral, addr
	}
	if addr, ok := fullWidthLiteral(host); ok {
		return hostLiteral, addr
	}
	if legacyIPv4Shape(host) {
		// Legacy-shaped but unparseable ("08", "300.1.2.3"): refused, never
		// resolved — a wildcard DNS answer must not resurrect it.
		return hostMalformed, netip.Addr{}
	}
	return hostName, netip.Addr{}
}

func classifyIPv6Literal(host string) (hostKind, netip.Addr) {
	if addr, ok := fullWidthLiteral(host); ok && !addr.Is4() {
		return hostLiteral, addr
	}
	return hostMalformed, netip.Addr{}
}

// validHostSyntax admits IPv6-looking input (handled elsewhere), legacy
// IPv4 shapes and full-width literals (classified next), and RFC 1123 LDH
// hostnames. Everything else is malformed before any resolution.
func validHostSyntax(host string) bool {
	if legacyIPv4Shape(host) {
		return true
	}
	if _, ok := fullWidthLiteral(host); ok {
		return true
	}
	return ldhHostname(host)
}

// malformedNumericCandidate refuses decorated or empty-labeled tokens whose
// core is a legacy IPv4 shape ("127.0.0.1.", ".1", "//127.0.0.1",
// "127.0.0.1/33"): close enough to an address that a loose downstream parser
// might accept them, so they must never reach one. Full-width prefix
// spellings ("127.0.0.1/32") are exempt: they denote exactly one address and
// are classified as literals.
func malformedNumericCandidate(host string) bool {
	trimmed := strings.TrimLeft(host, "%/")
	core := trimmed
	if end := strings.IndexAny(trimmed, "%/"); end >= 0 {
		core = trimmed[:end]
	}
	if core == host && !hasEmptyLabel(core) {
		return false
	}
	if !legacyIPv4Shape(core) {
		return false
	}
	_, full := fullWidthLiteral(host)
	return !full
}

func hasEmptyLabel(text string) bool {
	return slicesContainsEmpty(strings.Split(text, "."))
}

func slicesContainsEmpty(parts []string) bool {
	for _, part := range parts {
		if part == "" {
			return true
		}
	}
	return false
}

// legacyIPv4Shape reports whether text looks like an inet_aton spelling:
// one to four dot-separated components, each decimal ("123"), hex ("0x7f"),
// or octal-by-leading-zero — ignoring empty components so that decorated
// forms ("127..1", "127.0.0.1.") still register as numeric-shaped and are
// refused rather than resolved.
func legacyIPv4Shape(text string) bool {
	count := 0
	for _, part := range strings.Split(text, ".") {
		if part == "" {
			continue
		}
		if !legacyComponentShape(part) {
			return false
		}
		count++
	}
	return count >= 1 && count <= 4
}

func legacyComponentShape(part string) bool {
	digits := part
	hex := false
	if len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X") {
		digits = part[2:]
		hex = true
		if digits == "" {
			return false
		}
	}
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		decimal := c >= '0' && c <= '9'
		hexAlpha := hex && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')
		if !decimal && !hexAlpha {
			return false
		}
	}
	return true
}

// parseLegacyIPv4 implements the inet_aton grammar: 1-4 components, the
// last covering the remaining bytes; decimal, 0x-hex, or 0-octal, with
// leading-zero decimals always octal. Any overflow or stray byte fails —
// there is no permissive fallback.
func parseLegacyIPv4(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		value, ok := parseLegacyComponent(part)
		if !ok {
			return netip.Addr{}, false
		}
		values[i] = value
	}
	leading := values[:len(values)-1]
	last := values[len(values)-1]
	if last >= uint64(1)<<(8*(5-len(values))) {
		return netip.Addr{}, false
	}
	total := last
	for i, value := range leading {
		if value > 255 {
			return netip.Addr{}, false
		}
		total |= value << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{
		byte(total >> 24), byte(total >> 16), byte(total >> 8), byte(total),
	}), true
}

func parseLegacyComponent(part string) (uint64, bool) {
	base := 10
	digits := part
	switch {
	case len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X"):
		base = 16
		digits = part[2:]
	case len(part) > 1 && part[0] == '0':
		base = 8
		digits = part[1:]
	}
	if digits == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		return 0, false
	}
	return value, true
}

// fullWidthLiteral accepts exact address literals, including the full-width
// prefix spellings "a.b.c.d/32" and "x::y/128" that denote exactly one host
// address. Non-full-width prefixes are never normalized to an address.
func fullWidthLiteral(host string) (netip.Addr, bool) {
	if strings.Contains(host, "/") {
		prefix, err := netip.ParsePrefix(host)
		if err != nil || prefix.Addr().Zone() != "" {
			return netip.Addr{}, false
		}
		if prefix.Bits() != prefix.Addr().BitLen() {
			return netip.Addr{}, false
		}
		return prefix.Addr(), true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr, true
}

// ldhHostname enforces RFC 1123 LDH hostname grammar (one trailing dot
// admitted for absolute names) before any DNS query is made.
func ldhHostname(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !ldhLabel(label) {
			return false
		}
	}
	return true
}

func ldhLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		alnum := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		hyphen := c == '-' && i > 0 && i < len(label)-1
		if !alnum && !hyphen {
			return false
		}
	}
	return true
}
