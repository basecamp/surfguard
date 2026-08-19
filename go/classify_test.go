package surfguard

import (
	"math/rand"
	"net/netip"
	"testing"
)

// The oracles mirror the Ruby test suite's independent re-derivations of the
// policy from the tables; the pipeline in classify.go must agree with them
// at every probed point.

func ipv4DefaultOracle(addr netip.Addr) bool {
	return containsAny(disallowedIPv4, addr)
}

func ipv6DefaultOracle(addr netip.Addr) bool {
	switch {
	case containsAny(globallyReachableIETFAssignments, addr):
		return false
	case containsAny(disallowedIPv6, addr):
		return true
	case ietfProtocolAssignments.Contains(addr):
		return true
	default:
		return !containsAny(ianaAllocatedIPv6Unicast, addr)
	}
}

func defaultPolicyOracle(addr netip.Addr) bool {
	switch {
	case addr.Is4In6():
		return true
	case addr.Is4():
		return ipv4DefaultOracle(addr)
	case ipv4Compatible.Contains(addr):
		return true
	case nat64LocalUse.Contains(addr):
		return true
	case nat64WellKnown.Contains(addr) || ipv4Translatable.Contains(addr):
		return ipv4DefaultOracle(embeddedIPv4(addr))
	default:
		return ipv6DefaultOracle(addr)
	}
}

func strictPolicyOracle(addr netip.Addr) bool {
	switch {
	case defaultPolicyOracle(addr):
		return true
	case addr.Is4():
		return containsAny(ianaSpecialUseIPv4, addr)
	case containsAny(ianaSpecialUseIPv6, addr):
		return true
	case nat64WellKnown.Contains(addr) || ipv4Translatable.Contains(addr):
		return containsAny(ianaSpecialUseIPv4, embeddedIPv4(addr))
	default:
		return false
	}
}

// --- table audits: transcription is only trustworthy under count-and-membership

func TestDisallowedIPv4TranscriptionAudit(t *testing.T) {
	expected := []string{
		// lib/surfguard.rb DISALLOWED_IPV4, range for range.
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"168.63.129.16/32", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
		"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	}
	auditPrefixes(t, disallowedIPv4, expected)
}

func TestDisallowedIPv6TranscriptionAudit(t *testing.T) {
	expected := []string{
		// lib/surfguard.rb DISALLOWED_IPV6, range for range...
		"::/128", "100::/64", "100:0:0:1::/64", "2001::/32", "2001:2::/48",
		"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fec0::/10",
		"ff00::/8",
		// ...plus the ranges Ruby folds in via IPAddr predicates.
		"::1/128", "fc00::/7", "fe80::/10",
	}
	auditPrefixes(t, disallowedIPv6, expected)
}

func auditPrefixes(t *testing.T, actual []netip.Prefix, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("table has %d prefixes, audit list has %d", len(actual), len(expected))
	}
	for i, cidr := range expected {
		if actual[i] != netip.MustParsePrefix(cidr) {
			t.Errorf("table[%d] = %s, audit list says %s", i, actual[i], cidr)
		}
	}
}

// --- boundary regressions, mirroring test/surfguard_hardening_test.rb ------

func TestEveryAllocatedIPv6PrefixHasBeforeFirstLastAfterRegressions(t *testing.T) {
	for _, network := range ianaAllocatedIPv6Unicast {
		first := network.Masked().Addr()
		last := lastAddr(network)
		points := []netip.Addr{first, last}
		if before, ok := addrBefore(first); ok {
			points = append(points, before)
		}
		if after, ok := addrAfter(last); ok {
			points = append(points, after)
		}
		for _, addr := range points {
			if got, want := Blocked(addr), defaultPolicyOracle(addr); got != want {
				t.Errorf("%s at %s: Blocked = %v, oracle = %v", network, addr, got, want)
			}
		}
	}
}

func TestEveryExplicitDefaultDenyHasBeforeFirstLastAfterRegressions(t *testing.T) {
	for _, table := range [][]netip.Prefix{disallowedIPv4, disallowedIPv6} {
		for _, network := range table {
			first := network.Masked().Addr()
			last := lastAddr(network)
			points := []netip.Addr{first, last}
			if before, ok := addrBefore(first); ok {
				points = append(points, before)
			}
			if after, ok := addrAfter(last); ok {
				points = append(points, after)
			}
			for _, addr := range points {
				if got, want := Blocked(addr), defaultPolicyOracle(addr); got != want {
					t.Errorf("%s at %s: Blocked = %v, oracle = %v", network, addr, got, want)
				}
			}
		}
	}
}

func TestStrictPolicyBlocksEveryRegisteredSpecialUseEndpoint(t *testing.T) {
	strict := Policy{}.IANASpecialUse()
	for _, table := range [][]netip.Prefix{ianaSpecialUseIPv4, ianaSpecialUseIPv6} {
		for _, network := range table {
			for _, addr := range []netip.Addr{network.Masked().Addr(), lastAddr(network)} {
				if !strict.Blocked(addr) {
					t.Errorf("iana_special_use must block %s (from %s)", addr, network)
				}
			}
		}
	}
}

func TestNAT64PrefixesDoNotOverlap(t *testing.T) {
	if nat64WellKnown.Contains(netip.MustParseAddr("64:ff9b:1::1")) {
		t.Error("the WKP must not contain the local-use prefix")
	}
	if nat64LocalUse.Contains(netip.MustParseAddr("64:ff9b::1")) {
		t.Error("the local-use prefix must not contain the WKP")
	}
}

func TestSIITAndMappedPrefixesDoNotOverlap(t *testing.T) {
	if ipv4Translatable.Contains(netip.MustParseAddr("::ffff:169.254.169.254")) {
		t.Error("the translatable prefix must not contain mapped addresses")
	}
}

func TestInvalidAndZonedAddressesFailClosed(t *testing.T) {
	if !Blocked(netip.Addr{}) {
		t.Error("the zero Addr must be blocked")
	}
	zoned := netip.MustParseAddr("fe80::1%eth0")
	if !Blocked(zoned) {
		t.Error("zoned addresses must be blocked")
	}
	publicZoned := netip.MustParseAddr("2606:2800:220:1::1946").WithZone("eth0")
	if !Blocked(publicZoned) {
		t.Error("a zone on a public address still fails closed")
	}
}

// --- deterministic differential corpus, mirroring the Ruby 20k property test

func TestDeterministicClassifierPropertyCorpus(t *testing.T) {
	random := rand.New(rand.NewSource(0x5555246))
	strict := Policy{}.IANASpecialUse()
	for i := 0; i < 20000; i++ {
		var addr netip.Addr
		if i%2 == 0 {
			var raw [4]byte
			random.Read(raw[:])
			addr = netip.AddrFrom4(raw)
		} else {
			var raw [16]byte
			random.Read(raw[:])
			addr = netip.AddrFrom16(raw)
		}
		if got, want := Blocked(addr), defaultPolicyOracle(addr); got != want {
			t.Fatalf("%s: default Blocked = %v, oracle = %v", addr, got, want)
		}
		if got, want := strict.Blocked(addr), strictPolicyOracle(addr); got != want {
			t.Fatalf("%s: strict Blocked = %v, oracle = %v", addr, got, want)
		}
	}
}

// The transition-embedded space is a 2^-96 sliver the random corpus cannot
// reach; probe it directly with embedded IPv4 values drawn at random.
func TestDeterministicTransitionEmbeddingPropertyCorpus(t *testing.T) {
	random := rand.New(rand.NewSource(0x4e554d45))
	strict := Policy{}.IANASpecialUse()
	wkp := nat64WellKnown.Addr().As16()
	translatable := ipv4Translatable.Addr().As16()
	for i := 0; i < 5000; i++ {
		var v4 [4]byte
		random.Read(v4[:])
		embedded := netip.AddrFrom4(v4)
		for _, base := range [][16]byte{wkp, translatable} {
			raw := base
			copy(raw[12:], v4[:])
			addr := netip.AddrFrom16(raw)
			if got, want := Blocked(addr), ipv4DefaultOracle(embedded); got != want {
				t.Fatalf("%s: default Blocked = %v, embedded oracle = %v", addr, got, want)
			}
			if got, want := strict.Blocked(addr), strictPolicyOracle(addr); got != want {
				t.Fatalf("%s: strict Blocked = %v, oracle = %v", addr, got, want)
			}
		}
	}
}
