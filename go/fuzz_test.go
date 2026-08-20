package surfguard

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzBlocked(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1})
	f.Add([]byte{169, 254, 169, 254})
	f.Add([]byte{93, 184, 216, 34})
	f.Add(netip.MustParseAddr("64:ff9b::5db8:d822").AsSlice())
	f.Add(netip.MustParseAddr("::ffff:169.254.169.254").AsSlice())
	f.Add(netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946").AsSlice())
	f.Add(netip.MustParseAddr("2001:3::1").AsSlice())
	f.Fuzz(func(t *testing.T, data []byte) {
		var addr netip.Addr
		switch len(data) {
		case 4:
			addr = netip.AddrFrom4([4]byte(data))
		case 16:
			addr = netip.AddrFrom16([16]byte(data))
		default:
			return
		}
		strict := Policy{}.IANASpecialUse()
		blocked := Blocked(addr)
		strictBlocked := strict.Blocked(addr)

		// The strict policy is a strict superset of the default policy.
		if blocked && !strictBlocked {
			t.Fatalf("%s: default blocks but iana_special_use admits", addr)
		}
		// Mapped input is always refused in classification.
		if addr.Is4In6() && !blocked {
			t.Fatalf("%s: mapped input must be blocked", addr)
		}
		// NAT64-WKP decode consistency: wrapping an IPv4 in the WKP never
		// changes its default-policy verdict.
		if addr.Is4() {
			raw := nat64WellKnown.Addr().As16()
			copy(raw[12:], data)
			wrapped := netip.AddrFrom16(raw)
			if Blocked(wrapped) != blocked {
				t.Fatalf("%s: WKP wrapping changed the verdict", addr)
			}
		}
		// The classifier agrees with the independent oracles everywhere.
		if blocked != defaultPolicyOracle(addr) {
			t.Fatalf("%s: pipeline and oracle disagree (default)", addr)
		}
		if strictBlocked != strictPolicyOracle(addr) {
			t.Fatalf("%s: pipeline and oracle disagree (strict)", addr)
		}
	})
}

func FuzzLegacyIPv4Parser(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1", "2130706433", "0x7f000001", "127.1", "0177.0.0.01",
		"08", "0", "00", "1.2.3.4.5", "300.1.2.3", "4294967295", "0xffffffff",
		"169.254.43518", "1..2", "", "0x", "١٢٣", "127.0.0.1.",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		addr, ok := parseLegacyIPv4(input)
		if !ok {
			return
		}
		if !addr.Is4() {
			t.Fatalf("%q: parsed to non-IPv4 %s", input, addr)
		}
		// Differential: whenever netip accepts the same string, both parsers
		// must agree (netip accepts only canonical dotted-quads, a strict
		// subset of the legacy grammar).
		if reference, err := netip.ParseAddr(input); err == nil {
			if reference != addr {
				t.Fatalf("%q: legacy %s vs netip %s", input, addr, reference)
			}
		}
		// Round-trip: the canonical form re-parses to the same address.
		if again, ok := parseLegacyIPv4(addr.String()); !ok || again != addr {
			t.Fatalf("%q: canonical round-trip failed (%s)", input, addr)
		}
	})
}

func FuzzClassifyHost(f *testing.F) {
	for _, seed := range []string{
		"example.com", "127.0.0.1", "2130706433", "127.0.0.1.", "08",
		"::1", "64:ff9b::1", "not:a:valid:ipv6", "10.0.0.1/8", "93.184.216.34/32",
		"0xfoo.example", "1.2.3.4.5", "a-.example", "[::1]", "%", "127.1/8",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		normalized, err := normalizeHost(input)
		if err != nil {
			return
		}
		kind, addr := classifyHost(normalized)
		switch kind {
		case hostLiteral:
			if !addr.IsValid() || addr.Zone() != "" {
				t.Fatalf("%q: literal must be a valid unzoned address, got %v", input, addr)
			}
		case hostName:
			// Nothing colon-bearing or legacy-numeric-shaped may ever reach
			// DNS: that is the wildcard/search-domain bypass.
			if strings.Contains(normalized, ":") {
				t.Fatalf("%q: colon input classified as hostname", input)
			}
			if legacyIPv4Shape(normalized) {
				t.Fatalf("%q: legacy-shaped input classified as hostname", input)
			}
			if !ldhHostname(normalized) {
				t.Fatalf("%q: non-LDH input classified as hostname", input)
			}
		case hostMalformed:
			if addr.IsValid() {
				t.Fatalf("%q: malformed result carries an address", input)
			}
		}
	})
}
