package surfguard

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// ControlContext is the enforcement core: install it as net.Dialer's
// ControlContext and every socket connect attempt — each Happy Eyeballs
// race entrant, each redirect hop's dial, each connection-pool miss — is
// judged by its literal address at the moment of connection. There is no
// gap between the address checked and the address connected, which is what
// defeats DNS rebinding.
//
// Only tcp4/tcp6 are admitted. IPv4-mapped addresses are unmapped before
// judgment: at dial time the kernel really connects to the embedded IPv4.
// The port must be in the policy's allowed set (default 80 and 443;
// loopback under [Policy.AllowLoopback] is exempt).
func (p Policy) ControlContext(_ context.Context, network, address string, _ syscall.RawConn) error {
	return p.checkDial(network, address)
}

// Control is [Policy.ControlContext] without a context, for net.Dialer's
// Control field and APIs that take the two-argument form.
func (p Policy) Control(network, address string, _ syscall.RawConn) error {
	return p.checkDial(network, address)
}

func (p Policy) checkDial(network, address string) error {
	switch network {
	case "tcp4", "tcp6":
	default:
		// udp/unix/ip sockets would never reach an address check that
		// means anything here; refuse them at the network gate.
		return &Violation{Reason: ReasonNetwork}
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return &Violation{Host: address, Reason: ReasonMalformedHost}
	}
	addr := addrPort.Addr().Unmap()
	if p.Blocked(addr) {
		return &Violation{Addr: addr, Port: addrPort.Port(), Reason: ReasonBlockedAddr}
	}
	if !p.portAllowed(addr, addrPort.Port()) {
		return &Violation{Addr: addr, Port: addrPort.Port(), Reason: ReasonPort}
	}
	return nil
}

// DialContext dials with enforcement installed. Network may be "tcp",
// "tcp4", or "tcp6"; the resolved per-family attempts are each judged by
// [Policy.ControlContext].
//
// Address literals — including legacy inet_aton spellings like "2130706433"
// or "0x7f000001" — are canonicalized to their dotted/colon form before the
// dialer runs, so the numeric-host defense holds here too: the raw token is
// never handed to a resolver that might treat it as a name and follow a
// wildcard answer. Named hosts are left for the dialer to resolve, and every
// resulting address is judged by [Policy.ControlContext].
func (p Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &Violation{Reason: ReasonNetwork}
	}
	address, err := p.canonicalDialAddress(address)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:        30 * time.Second,
		KeepAlive:      30 * time.Second,
		ControlContext: p.ControlContext,
	}
	return dialer.DialContext(ctx, network, address)
}

// canonicalDialAddress rewrites a literal or legacy-numeric host to its
// canonical address form and refuses a malformed one, leaving named hosts
// untouched for the dialer to resolve.
func (p Policy) canonicalDialAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", &Violation{Host: address, Reason: ReasonMalformedHost}
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	kind, literal := classifyHost(normalized)
	switch kind {
	case hostMalformed:
		return "", &Violation{Host: host, Reason: ReasonMalformedHost}
	case hostLiteral:
		return net.JoinHostPort(literal.String(), port), nil
	default:
		return address, nil
	}
}
