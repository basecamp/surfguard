package surfguard

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
)

// fakeResolver is the deterministic DNS seam: it records every query so
// tests can assert that refused inputs never reach DNS, and its wildcard
// answer models a wildcard/search-domain response that would launder a
// numeric token into a public-looking record.
//
// Answers are split by family the way a real resolver does: 4-byte values
// answer "ip4", everything else — including an IPv4-mapped value, which is
// how a hostile AAAA is spelled — answers "ip6". With mapV4 set it models
// the pure-Go resolver instead, which returns A records in mapped form.
type fakeResolver struct {
	answers      map[string][]netip.Addr
	wildcard     []netip.Addr
	err          error
	errByNetwork map[string]error
	mapV4        bool
	queries      []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.queries = append(r.queries, host)
	if r.err != nil {
		return nil, r.err
	}
	if err, ok := r.errByNetwork[network]; ok {
		return nil, err
	}
	answer, ok := r.answers[host]
	if !ok {
		answer = r.wildcard
	}
	var family []netip.Addr
	for _, addr := range answer {
		if addr.Is4() != (network == "ip4") {
			continue
		}
		if network == "ip4" && r.mapV4 {
			addr = netip.AddrFrom16(addr.As16())
		}
		family = append(family, addr)
	}
	return family, nil
}

// queriedHosts returns the distinct hosts sent to DNS. Each name costs one
// query per address family, so counting calls would count families.
func (r *fakeResolver) queriedHosts() []string {
	var hosts []string
	for _, host := range r.queries {
		if !slices.Contains(hosts, host) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// crossFamilyResolver answers each network with exactly what it is told to,
// including wrong-family values a well-behaved resolver would never return.
type crossFamilyResolver struct {
	byNetwork map[string][]netip.Addr
}

func (r *crossFamilyResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	return r.byNetwork[network], nil
}

// cancelingResolver models a context that ends partway through resolution:
// it answers the IPv4 lookup normally and cancels on whichever family is
// named, so a partial answer is available when the context is already done.
type cancelingResolver struct {
	answer   []netip.Addr
	cancel   context.CancelFunc
	cancelOn string
}

func (r *cancelingResolver) LookupNetIP(ctx context.Context, network, _ string) ([]netip.Addr, error) {
	if network == r.cancelOn {
		r.cancel()
	}
	if network == "ip4" {
		return r.answer, nil
	}
	return nil, ctx.Err()
}

// idleCloseRecorder and plainRoundTripper stand in for transports with and
// without CloseIdleConnections.
type idleCloseRecorder struct{ closed bool }

func (r *idleCloseRecorder) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (r *idleCloseRecorder) CloseIdleConnections()                           { r.closed = true }

type plainRoundTripper struct{}

func (plainRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

func addrs(texts ...string) []netip.Addr {
	out := make([]netip.Addr, len(texts))
	for i, text := range texts {
		out[i] = netip.MustParseAddr(text)
	}
	return out
}

// lastAddr returns the highest address inside prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	masked := prefix.Masked()
	raw := masked.Addr().As16()
	bits := masked.Bits()
	offset := 0
	if masked.Addr().Is4() {
		offset = 12
	}
	total := len(raw)*8 - offset*8
	for i := bits; i < total; i++ {
		raw[offset+i/8] |= 1 << (7 - i%8)
	}
	if masked.Addr().Is4() {
		return netip.AddrFrom4([4]byte(raw[12:]))
	}
	return netip.AddrFrom16(raw)
}

func addrBefore(addr netip.Addr) (netip.Addr, bool) {
	prev := addr.Prev()
	return prev, prev.IsValid()
}

func addrAfter(addr netip.Addr) (netip.Addr, bool) {
	next := addr.Next()
	return next, next.IsValid()
}
