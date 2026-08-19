package surfguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
)

func TestResolvePublicAddrsFiltersBlockedAndOrdersIPv4First(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"mix.example": addrs("2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34", "169.254.169.254"),
	}}
	got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "mix.example")
	if err != nil {
		t.Fatal(err)
	}
	want := addrs("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolvePublicAddrsKeepsResolverOrderWithinEachFamily(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"many.example": addrs(
			"2606:2800:220:1::2", "11.0.0.2", "2606:2800:220:1::1", "11.0.0.1",
		),
	}}
	got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "many.example")
	if err != nil {
		t.Fatal(err)
	}
	want := addrs("11.0.0.2", "11.0.0.1", "2606:2800:220:1::2", "2606:2800:220:1::1")
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolvePublicAddrsEmptyWhenAllBlocked(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"bad.example": addrs("10.0.0.1", "169.254.169.254"),
	}}
	got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "bad.example")
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v; want empty and nil error (resolved-but-refused is not unresolvable)", got, err)
	}
}

func TestEmptyAnswerIsUnresolvableNotBlocked(t *testing.T) {
	resolver := &fakeResolver{}
	_, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "nope.example")
	if !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("want ErrUnresolvable, got %v", err)
	}
	if errors.Is(err, ErrBlocked) {
		t.Error("unresolvable must not match the ErrBlocked family: retry vs deactivate")
	}
	var unresolvable *UnresolvableError
	if !errors.As(err, &unresolvable) || unresolvable.Host != "nope.example" || unresolvable.Err != nil {
		t.Errorf("unexpected UnresolvableError contents: %+v", unresolvable)
	}
}

func TestResolverErrorIsWrappedButNeverPrinted(t *testing.T) {
	inner := errors.New("attacker-controlled resolver detail")
	resolver := &fakeResolver{err: inner}
	_, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "boom.example")
	if !errors.Is(err, ErrUnresolvable) || !errors.Is(err, inner) {
		t.Fatalf("want ErrUnresolvable wrapping the resolver error, got %v", err)
	}
	if err.Error() != ErrUnresolvable.Error() {
		t.Errorf("message must stay fixed, got %q", err.Error())
	}
}

func TestOversizedAndInvalidAnswersInvalidateTheLookup(t *testing.T) {
	flood := make([]netip.Addr, 257)
	for i := range flood {
		flood[i] = netip.MustParseAddr("93.184.216.34")
	}
	zoned := addrs("93.184.216.34")
	zoned = append(zoned, netip.MustParseAddr("2606:2800:220:1::1").WithZone("eth0"))
	invalid := []netip.Addr{{}}

	for label, answer := range map[string][]netip.Addr{
		"257 answers":    flood,
		"zoned answer":   zoned,
		"invalid answer": invalid,
	} {
		resolver := &fakeResolver{answers: map[string][]netip.Addr{"target.example": answer}}
		_, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "target.example")
		if !errors.Is(err, ErrUnresolvable) {
			t.Errorf("%s: want ErrUnresolvable, got %v", label, err)
		}
	}
}

func TestAnswersAreDeduplicatedInOrderAndCapAppliesToRawCount(t *testing.T) {
	dupes := make([]netip.Addr, 256)
	for i := range dupes {
		dupes[i] = netip.MustParseAddr("93.184.216.34")
	}
	resolver := &fakeResolver{answers: map[string][]netip.Addr{"dupes.example": dupes}}
	got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "dupes.example")
	if err != nil || !slices.Equal(got, addrs("93.184.216.34")) {
		t.Errorf("got %v, %v; want one deduplicated answer", got, err)
	}

	distinct := make([]netip.Addr, 256)
	base := netip.MustParseAddr("11.0.0.0").As4()
	for i := range distinct {
		raw := base
		raw[2] = byte(i >> 8)
		raw[3] = byte(i)
		distinct[i] = netip.AddrFrom4(raw)
	}
	resolver = &fakeResolver{answers: map[string][]netip.Addr{"many.example": distinct}}
	got, err = Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "many.example")
	if err != nil || len(got) != 256 {
		t.Errorf("256 distinct answers must be admitted; got %d, %v", len(got), err)
	}
}

func TestMappedAAAAAnswerIsFilteredAndRefused(t *testing.T) {
	// A hostile AAAA of ::ffff:169.254.169.254 must be treated as blocked,
	// not unwrapped into a v4 answer.
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"rebind.example": addrs("93.184.216.34", "::ffff:169.254.169.254"),
	}}
	policy := Policy{}.WithResolver(resolver)
	got, err := policy.ResolvePublicAddrs(context.Background(), "rebind.example")
	if err != nil || !slices.Equal(got, addrs("93.184.216.34")) {
		t.Errorf("got %v, %v; want the mapped answer filtered", got, err)
	}
	if err := policy.CheckURL(context.Background(), "https://rebind.example/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("CheckURL must refuse the mixed answer, got %v", err)
	}
	// Even a mapped PUBLIC answer is refused in classification input.
	if !Blocked(netip.MustParseAddr("::ffff:93.184.216.34")) {
		t.Error("mapped public addresses are hostile AAAA records, not targets")
	}
}

// The pure-Go resolver returns an A record as its IPv4-mapped 16-byte form.
// Judging that raw would refuse every IPv4 answer as a hostile mapped AAAA,
// so an ip4 answer is unmapped: both backends must classify identically.
func TestMappedIPv4AnswersFromThePureGoResolverAreOrdinaryIPv4(t *testing.T) {
	answer := addrs("93.184.216.34", "2606:2800:220:1::1")
	for _, mapV4 := range []bool{false, true} {
		resolver := &fakeResolver{
			answers: map[string][]netip.Addr{"dual.example": answer},
			mapV4:   mapV4,
		}
		policy := Policy{}.WithResolver(resolver)
		got, err := policy.ResolvePublicAddrs(context.Background(), "dual.example")
		if err != nil || !slices.Equal(got, answer) {
			t.Errorf("mapV4=%v: got %v, %v; want %v", mapV4, got, err, answer)
		}
		if err := policy.CheckURL(context.Background(), "https://dual.example/"); err != nil {
			t.Errorf("mapV4=%v: public dual-stack host must pass, got %v", mapV4, err)
		}
	}

	// Unmapping an ip4 answer must not launder a blocked one.
	resolver := &fakeResolver{
		answers: map[string][]netip.Addr{"meta.example": addrs("169.254.169.254")},
		mapV4:   true,
	}
	if err := (Policy{}).WithResolver(resolver).CheckURL(context.Background(), "https://meta.example/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("mapped metadata A record must stay blocked, got %v", err)
	}

	// A mapped value from the ip6 lookup is a genuine hostile AAAA and is
	// judged mapped, whatever the ip4 lookup spelled.
	hostile := netip.MustParseAddr("::ffff:93.184.216.34")
	resolver = &fakeResolver{
		answers: map[string][]netip.Addr{"hostile.example": {hostile}},
		mapV4:   true,
	}
	got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "hostile.example")
	if err != nil || len(got) != 0 {
		t.Errorf("hostile mapped AAAA must be filtered, got %v, %v", got, err)
	}
}

// The fake seam models the backends; this asserts against the real one, so
// the seam cannot drift from what net.Resolver actually returns. Under
// GODEBUG=netdns=go an A record arrives IPv4-mapped, which before the
// per-family lookup made ResolvePublicAddrs drop every IPv4 answer.
func TestRealResolverIPv4AnswersSurviveClassification(t *testing.T) {
	ctx := context.Background()
	raw, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "localhost")
	if err != nil || len(raw) == 0 {
		t.Skipf("no IPv4 answer for localhost on this host: %v, %v", raw, err)
	}
	got, err := Policy{}.AllowLoopback().ResolvePublicAddrs(ctx, "localhost")
	if err != nil {
		t.Fatalf("localhost must resolve, got %v", err)
	}
	if !slices.ContainsFunc(got, func(addr netip.Addr) bool { return addr.Is4() && addr.IsLoopback() }) {
		t.Errorf("want an IPv4 loopback answer, got %v (raw %v)", got, raw)
	}
}

func TestSingleFamilyNamesResolveThroughTheOtherFamilysFailure(t *testing.T) {
	// A v4-only name: the AAAA lookup errors (as real resolvers do) and the
	// A answer still stands — and the reverse.
	for _, c := range []struct {
		label   string
		answer  []netip.Addr
		failing string
	}{
		{"IPv4 only", addrs("93.184.216.34"), "ip6"},
		{"IPv6 only", addrs("2606:2800:220:1::1"), "ip4"},
	} {
		resolver := &fakeResolver{
			answers:      map[string][]netip.Addr{"single.example": c.answer},
			errByNetwork: map[string]error{c.failing: errors.New("no such host")},
		}
		got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "single.example")
		if err != nil || !slices.Equal(got, c.answer) {
			t.Errorf("%s: got %v, %v; want %v", c.label, got, err, c.answer)
		}
	}

	// Both families failing is unresolvable, and the reported cause is the
	// IPv4 error when there is one, the IPv6 error otherwise.
	v4Err, v6Err := errors.New("v4 down"), errors.New("v6 down")
	for _, c := range []struct {
		byNetwork map[string]error
		want      error
	}{
		{map[string]error{"ip4": v4Err, "ip6": v6Err}, v4Err},
		{map[string]error{"ip6": v6Err}, v6Err},
	} {
		resolver := &fakeResolver{errByNetwork: c.byNetwork}
		_, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "gone.example")
		if !errors.Is(err, ErrUnresolvable) || !errors.Is(err, c.want) {
			t.Errorf("%v: want ErrUnresolvable wrapping %v, got %v", c.byNetwork, c.want, err)
		}
	}
}

// Resolving per family means a context can end between the two lookups. The
// IPv4 answer alone is an incomplete picture of the host, so it must not
// become a verdict: approving on A records whose AAAA records were never seen
// is exactly the mixed-answer case CheckURL exists to refuse.
func TestCanceledContextFailsTheLookupDespiteAPartialAnswer(t *testing.T) {
	for _, cancelOn := range []string{"ip4", "ip6"} {
		ctx, cancel := context.WithCancel(context.Background())
		resolver := &cancelingResolver{
			answer:   addrs("93.184.216.34"),
			cancel:   cancel,
			cancelOn: cancelOn,
		}
		policy := Policy{}.WithResolver(resolver)

		err := policy.CheckURL(ctx, "https://partial.example/")
		if err == nil {
			t.Errorf("cancel on %s: a canceled lookup must not return a verdict", cancelOn)
		}
		if !errors.Is(err, ErrUnresolvable) || !errors.Is(err, context.Canceled) {
			t.Errorf("cancel on %s: want ErrUnresolvable wrapping context.Canceled, got %v", cancelOn, err)
		}
		if errors.Is(err, ErrBlocked) {
			t.Errorf("cancel on %s: cancellation is retryable, not a policy refusal", cancelOn)
		}

		if _, err := policy.ResolvePublicAddrs(ctx, "partial.example"); !errors.Is(err, ErrUnresolvable) {
			t.Errorf("cancel on %s: ResolvePublicAddrs must fail too, got %v", cancelOn, err)
		}
		cancel()
	}
}

func TestWrongFamilyAnswersInvalidateTheLookup(t *testing.T) {
	// A resolver that answers ip4 with a real IPv6 address, or ip6 with a
	// 4-byte one, is faulty — not partially trustworthy.
	for label, byNetwork := range map[string]map[string][]netip.Addr{
		"IPv6 from ip4":  {"ip4": addrs("2606:2800:220:1::1")},
		"IPv4 from ip6":  {"ip6": addrs("93.184.216.34")},
		"zoned from ip4": {"ip4": {netip.MustParseAddr("::ffff:93.184.216.34").WithZone("eth0")}},
	} {
		resolver := &crossFamilyResolver{byNetwork: byNetwork}
		_, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "bogus.example")
		if !errors.Is(err, ErrUnresolvable) {
			t.Errorf("%s: want ErrUnresolvable, got %v", label, err)
		}
	}
}

func TestAddressCapAppliesToTheCombinedAnswer(t *testing.T) {
	// Splitting the lookup must not double the ceiling: 128 + 129 raw
	// answers exceed the 256 cap even though neither family does.
	v4 := make([]netip.Addr, 128)
	base := netip.MustParseAddr("11.0.0.0").As4()
	for i := range v4 {
		raw := base
		raw[2], raw[3] = byte(i>>8), byte(i)
		v4[i] = netip.AddrFrom4(raw)
	}
	v6 := make([]netip.Addr, 129)
	base6 := netip.MustParseAddr("2606:2800:220:1::").As16()
	for i := range v6 {
		raw := base6
		raw[14], raw[15] = byte(i>>8), byte(i)
		v6[i] = netip.AddrFrom16(raw)
	}
	resolver := &fakeResolver{answers: map[string][]netip.Addr{"flood.example": append(slices.Clone(v4), v6...)}}
	_, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "flood.example")
	if !errors.Is(err, ErrUnresolvable) {
		t.Errorf("257 combined answers must invalidate the lookup, got %v", err)
	}

	// One fewer is admitted, proving the cap is the combined count.
	resolver = &fakeResolver{answers: map[string][]netip.Addr{"flood.example": append(slices.Clone(v4), v6[:128]...)}}
	got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), "flood.example")
	if err != nil || len(got) != 256 {
		t.Errorf("256 combined answers must be admitted; got %d, %v", len(got), err)
	}
}

func TestCheckURLRefusesMixedAnswers(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"mixed.example": addrs("93.184.216.34", "10.0.0.1"),
	}}
	err := Policy{}.WithResolver(resolver).CheckURL(context.Background(), "https://mixed.example/path")
	var violation *Violation
	if !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
		t.Fatalf("want blocked-address Violation, got %v", err)
	}
	if violation.Host != "mixed.example" || violation.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("violation should carry structured detail, got %+v", violation)
	}
	if violation.Error() != "surfguard: refusing blocked address" {
		t.Errorf("message must stay fixed, got %q", violation.Error())
	}
}

func TestCheckURLLiteralHostsSkipDNS(t *testing.T) {
	resolver := &fakeResolver{wildcard: addrs("93.184.216.34")}
	policy := Policy{}.WithResolver(resolver)
	if err := policy.CheckURL(context.Background(), "http://169.254.169.254/latest/meta-data/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("metadata literal must be refused, got %v", err)
	}
	if err := policy.CheckURL(context.Background(), "http://2130706433/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("legacy loopback literal must be refused, got %v", err)
	}
	if err := policy.CheckURL(context.Background(), "http://[::1]/"); !errors.Is(err, ErrBlocked) {
		t.Errorf("bracketed loopback literal must be refused, got %v", err)
	}
	if err := policy.CheckURL(context.Background(), "http://93.184.216.34/"); err != nil {
		t.Errorf("public literal must pass, got %v", err)
	}
	if len(resolver.queries) != 0 {
		t.Errorf("literal URLs must not reach DNS: %v", resolver.queries)
	}
}

func TestCheckURLMalformedInputs(t *testing.T) {
	resolver := &fakeResolver{wildcard: addrs("93.184.216.34")}
	policy := Policy{}.WithResolver(resolver)
	for _, rawURL := range []string{
		"http://",
		"::::not a url",
		"https://[fe80::1%25lo]/",
		"https://[v1.fe]/",
		"http://example\x00.com/",
		"http://93.184.216.34./",
	} {
		err := policy.CheckURL(context.Background(), rawURL)
		var violation *Violation
		if !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
			t.Errorf("%q: want malformed-host Violation, got %v", rawURL, err)
		}
	}
	if len(resolver.queries) != 0 {
		t.Errorf("malformed URLs must not reach DNS: %v", resolver.queries)
	}
}

func TestCheckURLAzureWireServerThroughEveryAPI(t *testing.T) {
	url := "http://168.63.129.16/machine/?comp=goalstate"
	policy := Policy{}
	if err := policy.CheckURL(context.Background(), url); !errors.Is(err, ErrBlocked) {
		t.Errorf("CheckURL must refuse the wire server, got %v", err)
	}
	got, err := policy.ResolvePublicAddrs(context.Background(), "168.63.129.16")
	if err != nil || len(got) != 0 {
		t.Errorf("ResolvePublicAddrs must filter the wire server, got %v, %v", got, err)
	}
	if !policy.BlockedHost("168.63.129.16") {
		t.Error("BlockedHost must refuse the wire server")
	}
}

func TestBlockedHostFailsClosedOnHostnames(t *testing.T) {
	if !BlockedHost("example.com") {
		t.Error("hostnames are unknowable without DNS; BlockedHost fails closed")
	}
	if BlockedHost("93.184.216.34") {
		t.Error("public literals are admitted")
	}
	if !BlockedHost("") || !BlockedHost("127.0.0.1%lo") {
		t.Error("malformed hosts fail closed")
	}
}

func TestPackageLevelConveniencesDelegateToTheDefaultPolicy(t *testing.T) {
	if !Blocked(netip.MustParseAddr("169.254.169.254")) {
		t.Error("Blocked")
	}
	if err := CheckURL(context.Background(), "http://127.0.0.1/"); !errors.Is(err, ErrBlocked) {
		t.Error("CheckURL")
	}
	got, err := ResolvePublicAddrs(context.Background(), "169.254.169.254")
	if err != nil || len(got) != 0 {
		t.Error("ResolvePublicAddrs")
	}
}
