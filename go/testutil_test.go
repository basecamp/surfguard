package surfguard

import (
	"context"
	"net/netip"
)

// fakeResolver is the deterministic DNS seam: it records every query so
// tests can assert that refused inputs never reach DNS, and its wildcard
// answer models a wildcard/search-domain response that would launder a
// numeric token into a public-looking record.
type fakeResolver struct {
	answers  map[string][]netip.Addr
	wildcard []netip.Addr
	err      error
	queries  []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.queries = append(r.queries, host)
	if r.err != nil {
		return nil, r.err
	}
	if addrs, ok := r.answers[host]; ok {
		return addrs, nil
	}
	return r.wildcard, nil
}

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
