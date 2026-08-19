package surfguard

import (
	"context"
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
// Address literals — including legacy inet_aton spellings — are classified
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
		answers, err := p.lookup().LookupNetIP(ctx, "ip", normalized)
		if err != nil {
			return nil, &UnresolvableError{Host: host, Err: err}
		}
		valid, ok := normalizeAnswers(answers)
		if !ok || len(valid) == 0 {
			return nil, &UnresolvableError{Host: host}
		}
		return valid, nil
	default:
		return nil, &Violation{Host: host, Reason: ReasonMalformedHost}
	}
}

// normalizeAnswers bounds, validates, and dedupes a resolver answer. One
// invalid or zoned answer invalidates the whole lookup: a resolver that
// produces garbage cannot be partially trusted.
func normalizeAnswers(raw []netip.Addr) ([]netip.Addr, bool) {
	if len(raw) > maxAddresses {
		return nil, false
	}
	answers := make([]netip.Addr, 0, len(raw))
	seen := make(map[netip.Addr]struct{}, len(raw))
	for _, addr := range raw {
		if !addr.IsValid() || addr.Zone() != "" {
			return nil, false
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		answers = append(answers, addr)
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
	return host, nil
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
