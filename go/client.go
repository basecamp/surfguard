package surfguard

import (
	"net/http"
	"time"
)

// Transport returns a real *http.Transport wired to the enforcement layer.
// Proxying is deliberately disabled — with a proxy configured, dial-time
// checks would judge the proxy's address rather than the target's, which is
// the classic bypass in copy-pasted Control snippets. Do not set Proxy on
// the returned transport.
func (p Policy) Transport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           p.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// Client returns a real *http.Client enforcing the policy: every connection
// is judged at dial time via [Policy.ControlContext], every redirect hop is
// re-validated via [Policy.CheckRedirect], and requests time out after 30
// seconds (adjust on the returned client if needed — but keep some
// timeout: a policy-refused target should not be able to stall callers
// either).
func (p Policy) Client() *http.Client {
	return &http.Client{
		Transport:     p.Transport(),
		CheckRedirect: p.CheckRedirect(nil),
		Timeout:       30 * time.Second,
	}
}

// Client returns an *http.Client enforcing the default policy.
func Client() *http.Client { return Policy{}.Client() }
