package surfguard

import (
	"errors"
	"net/netip"
)

// ErrBlocked is the policy-refusal error family. Every refusal surfguard
// makes — blocked address, malformed host, refused port, network, scheme, or
// redirect — matches it via errors.Is, including through the url.Error and
// net.OpError wrappers added by net/http and net.
var ErrBlocked = errors.New("surfguard: refusing blocked address")

// ErrUnresolvable reports a lookup that came back empty or unusable. It is
// deliberately unrelated to [ErrBlocked]: unresolvable means the target may
// be retried later; blocked means the target should be refused outright. A
// caller that deactivates targets on ErrBlocked must not deactivate on
// ErrUnresolvable.
var ErrUnresolvable = errors.New("surfguard: host could not be resolved")

// Reason identifies which policy gate refused the request.
type Reason int

const (
	// ReasonBlockedAddr: the address is not publicly routable under the
	// active policy.
	ReasonBlockedAddr Reason = iota
	// ReasonMalformedHost: the host is not a well-formed hostname or
	// address literal. Malformed input always fails closed.
	ReasonMalformedHost
	// ReasonNetwork: the dial network was not tcp4/tcp6.
	ReasonNetwork
	// ReasonPort: the port is outside the policy's allowed set.
	ReasonPort
	// ReasonScheme: the URL scheme was not http or https.
	ReasonScheme
	// ReasonRedirectDowngrade: a redirect attempted an https→http downgrade.
	ReasonRedirectDowngrade
	// ReasonTooManyRedirects: the redirect hop cap was exceeded.
	ReasonTooManyRedirects
)

// String names the reason for structured logging. It never echoes input.
func (r Reason) String() string {
	switch r {
	case ReasonBlockedAddr:
		return "blocked-address"
	case ReasonMalformedHost:
		return "malformed-host"
	case ReasonNetwork:
		return "network"
	case ReasonPort:
		return "port"
	case ReasonScheme:
		return "scheme"
	case ReasonRedirectDowngrade:
		return "redirect-downgrade"
	case ReasonTooManyRedirects:
		return "too-many-redirects"
	default:
		return "blocked-address"
	}
}

func (r Reason) message() string {
	switch r {
	case ReasonMalformedHost:
		return "surfguard: refusing malformed address"
	case ReasonNetwork:
		return "surfguard: refusing non-TCP network"
	case ReasonPort:
		return "surfguard: refusing blocked port"
	case ReasonScheme:
		return "surfguard: refusing unsupported scheme"
	case ReasonRedirectDowngrade:
		return "surfguard: refusing redirect scheme downgrade"
	case ReasonTooManyRedirects:
		return "surfguard: refusing to follow more redirects"
	default:
		return "surfguard: refusing blocked address"
	}
}

// Violation is a policy refusal. Its Error text is a fixed message per
// [Reason] — never the host, address, or port, because refusal text tends to
// end up in user-visible responses and logs and must not disclose what was
// probed or what it resolved to. The structured fields are available via
// errors.As for callers that log deliberately.
//
// The redaction guarantee covers this surfguard error only. When a refusal
// surfaces through http.Client, net/http and net wrap it: Client.Do returns
// a *url.Error whose Error() prints the request URL, and a dial-time refusal
// is wrapped in a *net.OpError whose Error() prints the remote address.
// Callers that must not leak the target should classify with errors.Is
// (against [ErrBlocked]) and log the extracted *Violation — not the outer
// error's text.
type Violation struct {
	// Host is the host string the refusal applies to, when known.
	Host string
	// Addr is the refused address, when the refusal was address-level.
	Addr netip.Addr
	// Port is the refused port, when the refusal was connection-level.
	Port uint16
	// Reason identifies the gate that refused.
	Reason Reason
}

func (v *Violation) Error() string { return v.Reason.message() }

func (v *Violation) Unwrap() error { return ErrBlocked }

// UnresolvableError reports a host whose lookup returned no usable
// addresses. Its Error text is fixed; the underlying resolver error is
// reachable only through the Err field or errors.Is/As, never through the
// message (resolver errors embed attacker-controlled detail).
type UnresolvableError struct {
	// Host is the host that could not be resolved.
	Host string
	// Err is the underlying resolver error; nil when the lookup merely
	// returned no (valid) answers.
	Err error
}

func (u *UnresolvableError) Error() string { return ErrUnresolvable.Error() }

func (u *UnresolvableError) Unwrap() []error {
	if u.Err == nil {
		return []error{ErrUnresolvable}
	}
	return []error{ErrUnresolvable, u.Err}
}
