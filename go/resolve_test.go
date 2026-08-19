package surfguard

import (
	"context"
	"errors"
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
