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
//
// It judges addresses, not URL shape: an http.Transport dials
// req.URL.Hostname(), so a malformed authority is already normalized away by
// the time it is reached. Wrap it in [Policy.RoundTripper] — as
// [Policy.Client] does — to refuse malformed hosts as well.
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

// RoundTripper returns [Policy.Transport] wrapped in the URL-shape check,
// for callers assembling their own *http.Client. It validates the host of
// every request it carries — the initial one and each redirect hop — before
// delegating.
//
// This check cannot live at the dial layer: an http.Transport dials
// req.URL.Hostname(), which has already stripped the brackets from an
// authority, so by then a bracketed host is indistinguishable from a bare
// one. Nor can it be left to net/url: its IP-literal validation tightened
// after Go 1.23, this module's floor, where url.Parse still accepts
// "http://[example.com]/" and reports the host as the ordinary name
// "example.com".
func (p Policy) RoundTripper() http.RoundTripper {
	return roundTripper{next: p.Transport()}
}

// roundTripper refuses a malformed request URL before the transport can
// normalize the evidence away.
type roundTripper struct {
	next http.RoundTripper
}

func (r roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, &Violation{Reason: ReasonMalformedHost}
	}
	if err := schemeAllowed(req.URL.Scheme); err != nil {
		return nil, err
	}
	if _, err := hostOfURL(req.URL); err != nil {
		return nil, err
	}
	return r.next.RoundTrip(req)
}

// CloseIdleConnections forwards to the wrapped transport, which
// (*http.Client).CloseIdleConnections reaches only through this method — a
// wrapper without it would silently leak idle connections.
func (r roundTripper) CloseIdleConnections() {
	if closer, ok := r.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// Client returns a real *http.Client enforcing the policy: every request URL
// is checked for a well-formed host via [Policy.RoundTripper], every
// connection is judged at dial time via [Policy.ControlContext], every
// redirect hop is re-validated via [Policy.CheckRedirect], and requests time
// out after 30 seconds (adjust on the returned client if needed — but keep
// some timeout: a policy-refused target should not be able to stall callers
// either).
func (p Policy) Client() *http.Client {
	return &http.Client{
		Transport:     p.RoundTripper(),
		CheckRedirect: p.CheckRedirect(nil),
		Timeout:       30 * time.Second,
	}
}

// Client returns an *http.Client enforcing the default policy.
func Client() *http.Client { return Policy{}.Client() }
