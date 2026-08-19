package surfguard

import (
	"net/netip"
	"os"
	"regexp"
	"testing"
)

func TestZeroValueIsTheFullDefaultPolicy(t *testing.T) {
	var policy Policy
	if !policy.Blocked(netip.MustParseAddr("169.254.169.254")) {
		t.Error("zero value must enforce the default policy")
	}
	if policy.Blocked(netip.MustParseAddr("93.184.216.34")) {
		t.Error("zero value must admit public space")
	}
	if policy.maxRedirects() != 10 {
		t.Error("default redirect cap is 10")
	}
}

func TestDerivationsAccumulateAndDoNotAliasSiblings(t *testing.T) {
	parent := Policy{}.Allow(netip.MustParsePrefix("10.0.0.0/8"))
	left := parent.Allow(netip.MustParsePrefix("192.168.0.0/16"))
	right := parent.Allow(netip.MustParsePrefix("172.16.0.0/12"))

	ten := netip.MustParseAddr("10.1.2.3")
	oneNinetyTwo := netip.MustParseAddr("192.168.1.1")
	oneSeventyTwo := netip.MustParseAddr("172.16.0.1")

	if parent.Blocked(ten) || !parent.Blocked(oneNinetyTwo) || !parent.Blocked(oneSeventyTwo) {
		t.Error("parent must keep only its own allowance")
	}
	if left.Blocked(ten) || left.Blocked(oneNinetyTwo) || !left.Blocked(oneSeventyTwo) {
		t.Error("left child accumulates the parent allowance plus its own")
	}
	if right.Blocked(ten) || !right.Blocked(oneNinetyTwo) || right.Blocked(oneSeventyTwo) {
		t.Error("right child must not see the left child's allowance")
	}
}

func TestDenyBeatsAllowAndAllowLoopback(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	policy := Policy{}.AllowLoopback().Deny(netip.MustParsePrefix("127.0.0.0/8"))
	if !policy.Blocked(loopback) {
		t.Error("Deny must beat AllowLoopback")
	}
	ten := netip.MustParseAddr("10.1.2.3")
	policy = Policy{}.Allow(netip.MustParsePrefix("10.0.0.0/8")).Deny(netip.MustParsePrefix("10.1.0.0/16"))
	if !policy.Blocked(ten) {
		t.Error("Deny must beat Allow")
	}
	if policy.Blocked(netip.MustParseAddr("10.2.0.1")) {
		t.Error("the rest of the allowance survives")
	}
	public := netip.MustParseAddr("93.184.216.34")
	if !(Policy{}).Deny(netip.MustParsePrefix("93.184.216.0/24")).Blocked(public) {
		t.Error("Deny applies to otherwise-public space")
	}
}

func TestAllowOverridesDefaultTablesButNotStrictOrStructural(t *testing.T) {
	ten := netip.MustParseAddr("10.1.2.3")
	if (Policy{}).Allow(netip.MustParsePrefix("10.0.0.0/8")).Blocked(ten) {
		t.Error("Allow must re-admit default-table space")
	}
	// Allow reaches transition-embedded IPv4 through the decode re-check.
	embedded := netip.MustParseAddr("64:ff9b::a01:203") // wraps 10.1.2.3
	if (Policy{}).Allow(netip.MustParsePrefix("10.0.0.0/8")).Blocked(embedded) {
		t.Error("the decode path re-checks as IPv4, allowances included")
	}
	// Allow can re-admit unallocated IPv6 (documented, explicit trust).
	unallocated := netip.MustParseAddr("2000::1")
	if (Policy{}).Allow(netip.MustParsePrefix("2000::/16")).Blocked(unallocated) {
		t.Error("Allow overrides the allocated-unicast allowlist")
	}
	// Allow never overrides the IANASpecialUse tables...
	as112 := netip.MustParseAddr("192.175.48.1")
	strict := Policy{}.IANASpecialUse().Allow(netip.MustParsePrefix("192.175.48.0/24"))
	if !strict.Blocked(as112) {
		t.Error("Allow must not override the special-use tables")
	}
	// ...nor structural defenses.
	if !(Policy{}).Allow(netip.MustParsePrefix("64:ff9b:1::/48")).Blocked(netip.MustParseAddr("64:ff9b:1::1")) {
		t.Error("NAT64 local-use is structural: never decodable, never allowable")
	}
	if !(Policy{}).Allow(netip.MustParsePrefix("::/96")).Blocked(netip.MustParseAddr("::a9fe:a9fe")) {
		t.Error("IPv4-compatible space is structural")
	}
}

// Structural defenses are the refusals no Allow — however broad — can lift:
// invalid, zoned, IPv4-mapped, and IPv4-compatible addresses, the NAT64
// local-use prefix (never decodable), and the embedded-IPv4 reclassification
// of NAT64-WKP/SIIT forms. Allow reaches the *embedded* IPv4 (that is the
// re-check's job), but it can never make the wrapper itself bypass the decode.
func TestBroadAllowsCannotBypassStructuralDefenses(t *testing.T) {
	// The broadest conceivable v6 allow: the entire address space.
	everything := Policy{}.Allow(netip.MustParsePrefix("::/0")).Allow(netip.MustParsePrefix("0.0.0.0/0"))
	structural := map[string]netip.Addr{
		"IPv4-mapped metadata":     netip.MustParseAddr("::ffff:169.254.169.254"),
		"IPv4-mapped public":       netip.MustParseAddr("::ffff:93.184.216.34"),
		"IPv4-compatible metadata": netip.MustParseAddr("::169.254.169.254"),
		"NAT64 local-use":          netip.MustParseAddr("64:ff9b:1::5db8:d822"),
		"zoned public":             netip.MustParseAddr("2606:2800:220:1::1946").WithZone("eth0"),
		"invalid":                  {},
	}
	for label, addr := range structural {
		if !everything.Blocked(addr) {
			t.Errorf("a ::/0 + 0.0.0.0/0 allow must not admit %s (%s)", label, addr)
		}
	}
	// The embedded-IPv4 reclassification still fires under a broad allow: a
	// WKP/SIIT form wrapping a blocked IPv4 is judged by that IPv4. The allow
	// re-admits it only because the embedded address is now allowed — proving
	// the decode ran, not that the wrapper was waved through.
	wkpMetadata := netip.MustParseAddr("64:ff9b::a9fe:a9fe") // wraps 169.254.169.254
	if Blocked(wkpMetadata) != true {
		t.Fatal("precondition: WKP-wrapped metadata is blocked by default")
	}
	if everything.Blocked(wkpMetadata) {
		t.Error("a 0.0.0.0/0 allow reaches the embedded IPv4 via the decode re-check")
	}
	// A v6-only allow does NOT reach the embedded IPv4 (the re-check judges an
	// IPv4 address, which the v6 allow does not cover), so the wrapper stays
	// blocked — the decode is not a bypass.
	v6only := Policy{}.Allow(netip.MustParsePrefix("::/0"))
	if !v6only.Blocked(wkpMetadata) {
		t.Error("a v6-only allow must not admit a WKP form wrapping blocked IPv4")
	}
}

func TestAllowLoopbackAdmitsExactlyLoopbackEvenUnderStrict(t *testing.T) {
	policy := Policy{}.IANASpecialUse().AllowLoopback()
	if policy.Blocked(netip.MustParseAddr("127.0.0.1")) || policy.Blocked(netip.MustParseAddr("::1")) {
		t.Error("AllowLoopback must admit loopback under IANASpecialUse")
	}
	if policy.Blocked(netip.MustParseAddr("127.255.255.254")) {
		t.Error("the whole 127/8 range is loopback")
	}
	if !policy.Blocked(netip.MustParseAddr("10.0.0.1")) {
		t.Error("AllowLoopback must not admit anything else")
	}
	if !policy.Blocked(netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Error("mapped loopback in classification input stays structural")
	}
	if !policy.Blocked(netip.MustParseAddr("64:ff9b::7f00:1")) {
		t.Error("NAT64-wrapped loopback is not loopback")
	}
}

func TestDerivationPanics(t *testing.T) {
	assertPanics := func(label string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s must panic", label)
			}
		}()
		f()
	}
	assertPanics("invalid Allow prefix", func() { Policy{}.Allow(netip.Prefix{}) })
	assertPanics("invalid Deny prefix", func() { Policy{}.Deny(netip.Prefix{}) })
	assertPanics("port zero", func() { Policy{}.AllowPorts(0) })
	assertPanics("negative redirects", func() { Policy{}.MaxRedirects(-1) })
}

func TestMaxRedirectsEncoding(t *testing.T) {
	if got := (Policy{}).MaxRedirects(0).maxRedirects(); got != 0 {
		t.Errorf("MaxRedirects(0) = %d", got)
	}
	if got := (Policy{}).MaxRedirects(3).maxRedirects(); got != 3 {
		t.Errorf("MaxRedirects(3) = %d", got)
	}
}

func TestAllowAndDenyPrefixesAreMasked(t *testing.T) {
	// A prefix given with host bits set covers its whole masked range.
	policy := Policy{}.Deny(netip.MustParsePrefix("93.184.216.34/24"))
	if !policy.Blocked(netip.MustParseAddr("93.184.216.1")) {
		t.Error("deny prefixes must be masked to their network")
	}
}

func TestZeroDependencyModule(t *testing.T) {
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^require`).Match(gomod) {
		t.Fatal("the module must remain dependency-free; go.mod grew a require directive")
	}
}
