package surfguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
)

const (
	maxHostBytes = 255
	maxAddresses = 256
)

// ResolvePublicAddrs resolves host and returns every admitted address, IPv4
// before IPv6 with resolver order retained within each family — a
// deterministic failover order for callers that pin the selected address at
// connection time. Blocked answers are filtered, so a resolvable host whose
// every answer is blocked yields an empty slice and a nil error.
//
// Names are looked up per address family (see [Resolver]). Address literals
// — including legacy inet_aton spellings — are classified
// authoritatively without DNS. Malformed hosts return a [Violation] with
// [ReasonMalformedHost] (where Ruby's resolve_public_ips returns [] silently;
// Go callers check errors). An empty or invalid DNS answer returns an
// [UnresolvableError], which is deliberately not part of the [ErrBlocked]
// family: it means retry later, not deactivate.
func (p Policy) ResolvePublicAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := p.resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var ipv4, ipv6 []netip.Addr
	for _, addr := range addrs {
		switch {
		case p.Blocked(addr):
		case addr.Is4():
			ipv4 = append(ipv4, addr)
		default:
			ipv6 = append(ipv6, addr)
		}
	}
	return append(ipv4, ipv6...), nil
}

// CheckURL returns nil if and only if rawURL's host resolves and every
// answer is admitted under the policy. A mixed public+blocked answer is
// refused: an unpinned connect could pick the blocked one. Errors are
// [Violation] (blocked or malformed; matches [ErrBlocked]) or
// [UnresolvableError] (matches [ErrUnresolvable]).
//
// CheckURL judges addresses only. Scheme, port, and redirect policy are
// enforced by [Policy.Client]; DNS rebinding between this check and a later
// connect is only defeated by dial-time enforcement or caller pinning.
func (p Policy) CheckURL(ctx context.Context, rawURL string) error {
	host, err := urlHost(rawURL)
	if err != nil {
		return err
	}
	addrs, err := p.resolveHost(ctx, host)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if p.Blocked(addr) {
			return &Violation{Host: host, Addr: addr, Reason: ReasonBlockedAddr}
		}
	}
	return nil
}

// BlockedHost judges a host string without ever querying DNS: address
// literals (IPv6, dotted-quad, legacy inet_aton spellings, full-width
// prefixes) are classified; everything else — every hostname included — is
// reported blocked, because a name's addresses are unknowable without
// resolution.
//
// A false result therefore means "an admitted address literal", NOT "a safe
// host": it is never false for a name. Do not use it as an allow-gate for
// names — a hostname will always return true (fails closed). For names, use
// [Policy.ResolvePublicAddrs] or [Policy.CheckURL], and pin the returned
// addresses.
func (p Policy) BlockedHost(host string) bool {
	normalized, err := normalizeHost(host)
	if err != nil {
		return true
	}
	kind, literal := classifyHost(normalized)
	if kind == hostLiteral {
		return p.Blocked(literal)
	}
	return true
}

func (p Policy) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	normalized, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	kind, literal := classifyHost(normalized)
	switch kind {
	case hostLiteral:
		return []netip.Addr{literal}, nil
	case hostName:
		return p.lookupHost(ctx, host, normalized)
	default:
		return nil, &Violation{Host: host, Reason: ReasonMalformedHost}
	}
}

// lookupHost queries each address family separately. A combined "ip" lookup
// would lose whether an answer came from an A or a AAAA record, and the
// pure-Go resolver spells an A record as the IPv4-mapped 16-byte form
// (net.DefaultResolver.LookupNetIP(ctx, "ip", "localhost") yields
// ::ffff:127.0.0.1 under GODEBUG=netdns=go, where cgo yields 127.0.0.1).
// Classification refuses every mapped address as a hostile AAAA, so a
// combined lookup would drop ordinary IPv4 answers on that backend. Asking
// per family restores the identity: an "ip4" answer is an A record and is
// unmapped before judgment, while a mapped "ip6" answer is a genuine hostile
// AAAA and stays refused.
//
// The two lookups run concurrently, as a combined "ip" lookup does
// internally, so splitting them costs no extra round trip.
//
// A verdict is only ever formed from a complete picture of the host. A family
// may be missing, but only definitively: no error, or a lookup that says the
// records do not exist. A timeout, SERVFAIL, or any other indefinite failure
// leaves it unknown whether that family had addresses worth refusing, so the
// host is reported unresolvable rather than judged on the other family alone.
func (p Policy) lookupHost(ctx context.Context, host, normalized string) ([]netip.Addr, error) {
	resolver := p.lookup()
	var v6 []netip.Addr
	var err6 error
	done := make(chan struct{})
	go func() {
		defer close(done)
		v6, err6 = resolver.LookupNetIP(ctx, "ip6", normalized)
	}()
	v4, err4 := resolver.LookupNetIP(ctx, "ip4", normalized)
	<-done

	// A context that ends mid-resolution must not yield a verdict either: the
	// answers in hand are whatever arrived before the caller gave up.
	if err := ctx.Err(); err != nil {
		return nil, &UnresolvableError{Host: host, Err: err}
	}
	for _, err := range []error{err4, err6} {
		if !definitiveAnswer(err) {
			return nil, &UnresolvableError{Host: host, Err: err}
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		err := err4
		if err == nil {
			err = err6
		}
		return nil, &UnresolvableError{Host: host, Err: err}
	}
	valid, ok := normalizeAnswers(v4, v6)
	if !ok || len(valid) == 0 {
		return nil, &UnresolvableError{Host: host}
	}
	return valid, nil
}

// definitiveAnswer reports whether a per-family lookup result settles what
// that family holds. Success settles it, and so does a resolver saying the
// records do not exist — that is the ordinary single-family host. Every other
// failure is indefinite: the family may hold addresses that would have been
// refused, and none of them were seen.
func definitiveAnswer(err error) bool {
	if err == nil {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// normalizeAnswers bounds, validates, and dedupes a per-family resolver
// answer, IPv4 before IPv6. The bound applies to the combined raw count, so
// splitting the lookup cannot double the ceiling. One invalid, zoned, or
// wrong-family answer invalidates the whole lookup: a resolver that produces
// garbage cannot be partially trusted.
func normalizeAnswers(v4, v6 []netip.Addr) ([]netip.Addr, bool) {
	if len(v4)+len(v6) > maxAddresses {
		return nil, false
	}
	answers := make([]netip.Addr, 0, len(v4)+len(v6))
	seen := make(map[netip.Addr]struct{}, len(v4)+len(v6))
	add := func(addr netip.Addr) {
		if _, dup := seen[addr]; dup {
			return
		}
		seen[addr] = struct{}{}
		answers = append(answers, addr)
	}
	for _, addr := range v4 {
		// An "ip4" answer is an A record; the mapped spelling is a
		// representation detail of the backend, so unmap it and judge the
		// IPv4 address it names. Anything not IPv4 in either spelling is a
		// resolver fault.
		if !addr.IsValid() || addr.Zone() != "" || !addr.Unmap().Is4() {
			return nil, false
		}
		add(addr.Unmap())
	}
	for _, addr := range v6 {
		// An "ip6" answer is a AAAA record and is judged as it stands: a
		// mapped value here is the hostile-AAAA case and must stay mapped so
		// classification refuses it. A 4-byte answer is a resolver fault.
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4() {
			return nil, false
		}
		add(addr)
	}
	return answers, true
}

func normalizeHost(host string) (string, error) {
	malformed := &Violation{Host: host, Reason: ReasonMalformedHost}
	if host == "" || len(host) > maxHostBytes {
		return "", malformed
	}
	for i := 0; i < len(host); i++ {
		// ASCII-only, no NUL; '%' refuses IPv6 zone identifiers in any
		// spelling before a parser could interpret them.
		if host[i] == 0 || host[i] >= 0x80 || host[i] == '%' {
			return "", malformed
		}
	}
	return host, nil
}

func urlHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", &Violation{Reason: ReasonMalformedHost}
	}
	return hostOfURL(u)
}

func hostOfURL(u *url.URL) (string, error) {
	host := u.Hostname()
	if host == "" {
		return "", &Violation{Reason: ReasonMalformedHost}
	}
	// A bracketed authority is an IP-literal (RFC 3986). Require a valid
	// unzoned IPv6 address rather than letting Hostname() strip the brackets
	// and hand back a name — covers [example.com], IPvFuture [v1.fe], and
	// bracketed IPv4. net/url rejects most of these at Parse time; this also
	// guards hand-built *url.URL values (e.g. redirect targets) and keeps the
	// bracket contract local.
	if len(u.Host) > 0 && u.Host[0] == '[' && !bracketedHostIsIPv6(host) {
		return "", &Violation{Host: u.Host, Reason: ReasonMalformedHost}
	}
	// Apply the same host gate the resolution layer uses — ASCII-only,
	// bounded, no NUL, no zone identifier — so every URL entry point refuses
	// the same spellings. It matters most for a non-ASCII authority:
	// http.Transport IDNA-normalizes one before dialing (U+24DB "ⓛocalhost"
	// becomes "localhost"), so a host left unchecked here reaches the dialer
	// as a different host than the one judged.
	return normalizeHost(host)
}

// bracketedHostIsIPv6 reports whether host (brackets already stripped) is a
// valid unzoned IPv6 literal. IPv4-mapped forms are accepted here and refused
// later by classification, matching the non-bracketed path.
func bracketedHostIsIPv6(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is6() && addr.Zone() == ""
}

// ResolvePublicAddrs resolves host under the default policy.
func ResolvePublicAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	return Policy{}.ResolvePublicAddrs(ctx, host)
}

// CheckURL checks rawURL under the default policy.
func CheckURL(ctx context.Context, rawURL string) error {
	return Policy{}.CheckURL(ctx, rawURL)
}

// BlockedHost judges a host string under the default policy without DNS.
func BlockedHost(host string) bool { return Policy{}.BlockedHost(host) }
