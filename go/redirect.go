package surfguard

import (
	"net/http"
	"strings"
)

// CheckRedirect returns an http.Client CheckRedirect function that enforces
// redirect policy (pass nil for next, or a caller callback to run alongside).
//
// The caller callback runs first. Any non-nil result it returns — including
// http.ErrUseLastResponse — stops the client from following the redirect, so
// no unvalidated request is ever sent; that result is returned unchanged.
// Only when the caller approves (returns nil, having possibly mutated the
// request) does the policy validate, and it validates the request that will
// actually go on the wire:
//
//   - Hop cap: at most [Policy.MaxRedirects] redirects (default 10; 0
//     follows none).
//   - Scheme: only http and https, and never an https→http downgrade — the
//     dial layer cannot see schemes, so this is the one redirect property
//     that must be enforced here.
//   - Host: literal and numeric Location hosts are classified synchronously
//     and refused when blocked or malformed. Named hosts pass — their
//     addresses are judged at dial time by [Policy.ControlContext], which
//     re-runs for every hop.
//
// The policy is not skippable: a caller who returns nil cannot cause a fetch
// to a refused target, because validation runs after their callback on the
// final request.
func (p Policy) CheckRedirect(next func(req *http.Request, via []*http.Request) error) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// Snapshot the source (previous hop) scheme BEFORE the caller's
		// callback runs. The callback receives the via[] request pointers and
		// can mutate them; without this snapshot it could rewrite an https
		// origin to http and slip an https→http downgrade past the check
		// below. The target scheme, by contrast, is read after the callback,
		// because policy must validate the request that will actually be sent.
		sourceScheme := priorHopScheme(via)
		if next != nil {
			if err := next(req, via); err != nil {
				return err
			}
		}
		if len(via) > p.maxRedirects() {
			return &Violation{Reason: ReasonTooManyRedirects}
		}
		if req == nil || req.URL == nil {
			return &Violation{Reason: ReasonMalformedHost}
		}
		scheme := strings.ToLower(req.URL.Scheme)
		if scheme != "http" && scheme != "https" {
			return &Violation{Reason: ReasonScheme}
		}
		if strings.EqualFold(sourceScheme, "https") && scheme == "http" {
			return &Violation{Reason: ReasonRedirectDowngrade}
		}
		return p.checkRedirectHost(req)
	}
}

func priorHopScheme(via []*http.Request) string {
	if len(via) > 0 && via[len(via)-1] != nil && via[len(via)-1].URL != nil {
		return via[len(via)-1].URL.Scheme
	}
	return ""
}

func (p Policy) checkRedirectHost(req *http.Request) error {
	host, err := hostOfURL(req.URL)
	if err != nil {
		return err
	}
	kind, literal := classifyHost(host)
	switch kind {
	case hostMalformed:
		return &Violation{Host: host, Reason: ReasonMalformedHost}
	case hostLiteral:
		if p.Blocked(literal) {
			return &Violation{Host: host, Addr: literal, Reason: ReasonBlockedAddr}
		}
	}
	return nil
}
