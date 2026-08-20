package surfguard

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func violationReason(t *testing.T, err error, want Reason) *Violation {
	t.Helper()
	var violation *Violation
	if !errors.As(err, &violation) || violation.Reason != want {
		t.Fatalf("want Violation reason %v, got %v", want, err)
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatal("every Violation must match the ErrBlocked family")
	}
	return violation
}

func TestControlRefusesNonTCPNetworks(t *testing.T) {
	for _, network := range []string{"udp4", "udp6", "unix", "ip4", "tcp", "udp"} {
		err := Policy{}.Control(network, "93.184.216.34:80", nil)
		violationReason(t, err, ReasonNetwork)
	}
}

func TestControlJudgesTheLiteralAddress(t *testing.T) {
	policy := Policy{}
	if err := policy.Control("tcp4", "93.184.216.34:443", nil); err != nil {
		t.Errorf("public:443 must pass, got %v", err)
	}
	err := policy.Control("tcp4", "169.254.169.254:80", nil)
	violation := violationReason(t, err, ReasonBlockedAddr)
	if violation.Addr != netip.MustParseAddr("169.254.169.254") || violation.Port != 80 {
		t.Errorf("violation should carry the judged endpoint, got %+v", violation)
	}
	violationReason(t, policy.Control("tcp6", "[fd00:ec2::254]:80", nil), ReasonBlockedAddr)
	violationReason(t, policy.Control("tcp4", "not-an-endpoint", nil), ReasonMalformedHost)
	violationReason(t, policy.Control("tcp6", "example.com:80", nil), ReasonMalformedHost)
}

func TestControlUnmapsMappedAddressesBeforeJudging(t *testing.T) {
	// At dial time the kernel connects to the embedded IPv4, so the mapped
	// form is judged as that IPv4 — blocked when it is loopback...
	violationReason(t, Policy{}.Control("tcp6", "[::ffff:127.0.0.1]:80", nil), ReasonBlockedAddr)
	violationReason(t, Policy{}.Control("tcp6", "[::ffff:10.0.0.1]:80", nil), ReasonBlockedAddr)
	// ...admitted when it is public...
	if err := (Policy{}).Control("tcp6", "[::ffff:93.184.216.34]:80", nil); err != nil {
		t.Errorf("mapped public must be admitted at dial time, got %v", err)
	}
	// ...and reachable under AllowLoopback, matching what the kernel does.
	if err := (Policy{}).AllowLoopback().Control("tcp6", "[::ffff:127.0.0.1]:8080", nil); err != nil {
		t.Errorf("AllowLoopback must admit mapped loopback at dial time, got %v", err)
	}
}

func TestControlEnforcesPortPolicy(t *testing.T) {
	violation := violationReason(t, Policy{}.Control("tcp4", "93.184.216.34:8080", nil), ReasonPort)
	if violation.Port != 8080 {
		t.Errorf("violation should carry the refused port, got %+v", violation)
	}
	if err := (Policy{}).AllowPorts(8080).Control("tcp4", "93.184.216.34:8080", nil); err != nil {
		t.Errorf("AllowPorts(8080) must admit it, got %v", err)
	}
	// AllowPorts replaces the default set: 80/443 must now be named to pass.
	violationReason(t, Policy{}.AllowPorts(8080).Control("tcp4", "93.184.216.34:443", nil), ReasonPort)
	if err := (Policy{}).AllowPorts(8080).AllowPorts(443).Control("tcp4", "93.184.216.34:443", nil); err != nil {
		t.Errorf("AllowPorts accumulates, got %v", err)
	}
	if err := (Policy{}).AllowAllPorts().Control("tcp4", "93.184.216.34:6379", nil); err != nil {
		t.Errorf("AllowAllPorts, got %v", err)
	}
	// Address policy still applies with open ports.
	violationReason(t, Policy{}.AllowAllPorts().Control("tcp4", "10.0.0.1:6379", nil), ReasonBlockedAddr)
	// Loopback under AllowLoopback is exempt (httptest binds random ports).
	if err := (Policy{}).AllowLoopback().Control("tcp4", "127.0.0.1:49321", nil); err != nil {
		t.Errorf("AllowLoopback exempts loopback from port policy, got %v", err)
	}
	violationReason(t, Policy{}.AllowLoopback().Control("tcp4", "93.184.216.34:49321", nil), ReasonPort)
}

func TestControlContextMatchesControl(t *testing.T) {
	err := Policy{}.ControlContext(context.Background(), "tcp4", "169.254.169.254:80", nil)
	violationReason(t, err, ReasonBlockedAddr)
}

// The rebinding scenario: the pre-flight check sees a public answer, the
// attacker's DNS then answers with a private address. Control judges the
// dialed address itself, so the swap is caught regardless.
func TestRebindingBetweenCheckAndDialIsCaughtAtControl(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]netip.Addr{
		"rebind.example": addrs("93.184.216.34"),
	}}
	policy := Policy{}.WithResolver(resolver)
	if err := policy.CheckURL(context.Background(), "https://rebind.example/"); err != nil {
		t.Fatalf("pre-flight with a public answer must pass, got %v", err)
	}
	// The rebound answer arrives at dial time as the literal address.
	violationReason(t, policy.Control("tcp4", "10.0.0.1:443", nil), ReasonBlockedAddr)
}

func TestDialContextCanonicalizesLegacyNumericHostsBeforeDialing(t *testing.T) {
	// A blocked legacy/literal spelling is canonicalized to its address and
	// refused by Control BEFORE any socket or resolver call — so the numeric
	// token never reaches a resolver that might treat it as a name and follow
	// a wildcard answer. A resolver error (rather than a blocked-address
	// Violation) here would prove canonicalization was skipped.
	for _, address := range []string{
		"2130706433:80", // 127.0.0.1
		"0x7f000001:80", // 127.0.0.1
		"127.1:80",      // 127.0.0.1
		"2852039166:80", // 169.254.169.254
		"[::1]:80",      // loopback literal
		"[::ffff:127.0.0.1]:80",
	} {
		_, err := Policy{}.DialContext(context.Background(), "tcp", address)
		violationReason(t, err, ReasonBlockedAddr)
	}
	// A malformed numeric host is refused at the gate, never resolved.
	_, err := Policy{}.DialContext(context.Background(), "tcp", "93.184.216.34.:80")
	violationReason(t, err, ReasonMalformedHost)
	_, err = Policy{}.DialContext(context.Background(), "tcp", "no-port-here")
	violationReason(t, err, ReasonMalformedHost)
}

func TestCanonicalDialAddress(t *testing.T) {
	policy := Policy{}
	// Literal and legacy spellings are rewritten to canonical form.
	for address, want := range map[string]string{
		"2130706433:80":         "127.0.0.1:80",
		"0x7f000001:443":        "127.0.0.1:443",
		"93.184.216.34:80":      "93.184.216.34:80",
		"[::1]:80":              "[::1]:80",
		"[::ffff:127.0.0.1]:80": "[::ffff:127.0.0.1]:80",
	} {
		got, err := policy.canonicalDialAddress(address)
		if err != nil || got != want {
			t.Errorf("canonicalDialAddress(%q) = %q, %v; want %q", address, got, err, want)
		}
	}
	// Named hosts pass through untouched for the dialer to resolve.
	if got, err := policy.canonicalDialAddress("example.com:80"); err != nil || got != "example.com:80" {
		t.Errorf("named host: got %q, %v", got, err)
	}
	// Malformed addresses fail closed before any resolver call.
	for _, address := range []string{
		"no-port",           // missing port
		"[fe80::1%eth0]:80", // zoned bracketed literal
		"93.184.216.34.:80", // malformed numeric host
		"[example.com]:80",  // bracketed authority must be IPv6, not a name
		"[v1.com]:80",       // bracketed IPvFuture
		"[127.0.0.1]:80",    // bracketed IPv4 is malformed per RFC 3986
		"bad%host:80",       // unbracketed host refused by normalizeHost
	} {
		if _, err := policy.canonicalDialAddress(address); !errors.Is(err, ErrBlocked) {
			t.Errorf("canonicalDialAddress(%q) must refuse, got %v", address, err)
		}
	}
}

// net.SplitHostPort validates only the delimiter, so an out-of-range numeric
// port reached net.Dialer and came back as an untyped *net.OpError after the
// policy had already approved the address.
func TestDialContextRefusesOutOfRangeNumericPorts(t *testing.T) {
	for _, address := range []string{
		"example.com:65536",
		"93.184.216.34:99999",
		"example.com:4294967296",
	} {
		_, err := Policy{}.AllowAllPorts().DialContext(context.Background(), "tcp", address)
		violationReason(t, err, ReasonPort)
	}

	// A non-numeric port is a service name: net.Dialer resolves it and
	// ControlContext judges the numeric result, so it must not be refused
	// here. "example.com:http" fails to connect in a sandbox, but it must
	// fail as something other than our port refusal.
	if err := dialPortAllowed("example.com", "http"); err != nil {
		t.Errorf("a service name must reach the dialer, got %v", err)
	}
	if err := dialPortAllowed("example.com", ""); err != nil {
		t.Errorf("an empty port must reach the dialer, got %v", err)
	}
	if err := dialPortAllowed("example.com", "443"); err != nil {
		t.Errorf("an ordinary port must pass, got %v", err)
	}
}

func TestDialContextRefusesBlockedTargetsWithoutConnecting(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()

	_, err := Policy{}.DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("strict dial to loopback must be refused, got %v", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("dialer failures surface as *net.OpError, got %T", err)
	}

	conn, err := Policy{}.AllowLoopback().DialContext(context.Background(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("AllowLoopback dial must succeed, got %v", err)
	}
	conn.Close()

	if _, err := (Policy{}).DialContext(context.Background(), "udp", "93.184.216.34:53"); !errors.Is(err, ErrBlocked) {
		t.Errorf("non-TCP networks are refused at the gate, got %v", err)
	}
}
