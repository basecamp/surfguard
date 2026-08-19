package surfguard

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDefaultsAreHardened(t *testing.T) {
	transport := Policy{}.Transport()
	if transport.Proxy != nil {
		t.Error("Proxy must be nil: a proxy would be validated instead of the target")
	}
	if transport.DialContext == nil || !transport.ForceAttemptHTTP2 {
		t.Error("transport must dial through the policy with HTTP/2 enabled")
	}
	client := Policy{}.Client()
	if client.Timeout == 0 {
		t.Error("client must have a timeout")
	}
	if client.CheckRedirect == nil {
		t.Error("client must re-validate redirects")
	}
	if Client().Transport == nil {
		t.Error("package-level Client delegates")
	}
	if _, ok := client.Transport.(roundTripper); !ok {
		t.Errorf("client must validate URL shape before the transport, got %T", client.Transport)
	}
}

// A bracketed authority is an IP-literal (RFC 3986). net/url tightened its
// IP-literal validation after Go 1.23 — this module's floor — where
// url.Parse still accepts "http://[example.com]/" and reports the host as the
// ordinary name "example.com". The transport then dials req.URL.Hostname(),
// which has already dropped the brackets, so nothing downstream can tell the
// difference: on Go 1.23 this fetched a bracketed name before the round
// tripper began checking URL shape.
func TestClientRefusesBracketedNonIPv6Authorities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// AllowLoopback and AllowAllPorts would admit this fixture by address and
	// port, so anything fetched here is the malformed host getting through,
	// not a policy decision.
	client := Policy{}.AllowLoopback().AllowAllPorts().Client()
	for _, host := range []string{"[localhost]", "[example.com]", "[v1.com]", "[127.0.0.1]"} {
		rawURL := "http://" + host + ":" + port + "/"
		response, err := client.Get(rawURL)
		if err == nil {
			response.Body.Close()
			t.Errorf("%s must be refused, got %s", rawURL, response.Status)
			continue
		}
		// Where the toolchain's url.Parse accepts the spelling, the refusal
		// has to be ours; where it rejects it, the request never starts.
		if _, parseErr := url.Parse(rawURL); parseErr == nil && !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want ErrBlocked, got %v", rawURL, err)
		}
	}

	// The same fixture by its ordinary authority still fetches, so the check
	// refuses the bracket spelling and nothing more.
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unbracketed fixture must still fetch, got %v", err)
	}
	response.Body.Close()
}

// url.Parse is not the only way a request URL is built: a caller can
// construct one directly, and every toolchain carries it to the transport
// unexamined. Drive the round tripper with hand-built requests so the check
// is exercised regardless of how strict the toolchain's parser is.
func TestRoundTripperValidatesHandBuiltRequestURLs(t *testing.T) {
	transport := Policy{}.AllowLoopback().AllowAllPorts().RoundTripper()
	for _, host := range []string{
		"[example.com]",    // bracketed name
		"[v1.fe]",          // IPvFuture
		"[127.0.0.1]",      // bracketed IPv4
		"[fe80::1%25eth0]", // zoned literal
		"",                 // no host at all
	} {
		request := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "http", Host: host}}
		_, err := transport.RoundTrip(request)
		violationReason(t, err, ReasonMalformedHost)
	}

	// A nil request or URL fails closed rather than panicking.
	if _, err := transport.RoundTrip(nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("nil request must fail closed, got %v", err)
	}
	if _, err := transport.RoundTrip(&http.Request{Method: http.MethodGet}); !errors.Is(err, ErrBlocked) {
		t.Errorf("nil URL must fail closed, got %v", err)
	}
}

// http.Transport IDNA-normalizes a non-ASCII authority before it reaches
// DialContext — U+24DB "ⓛocalhost" maps to "localhost" — so the spelling the
// policy judged is not the host that gets dialed. The module does no IDN
// conversion by construction, so a non-ASCII host must be refused outright
// rather than silently folded into another one.
func TestClientRefusesNonASCIIAuthorities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	client := Policy{}.AllowLoopback().AllowAllPorts().Client()
	for _, host := range []string{
		"ⓛocalhost",  // U+24DB folds to "l"
		"lÖcalhost",  // encoded as punycode
		"localhost。", // U+3002 folds to "."
		"１２７.０.０.１",  // full-width digits fold to a dotted-quad literal
		"２１３０７０６４３３", // ...and to a legacy inet_aton spelling of it
	} {
		rawURL := "http://" + host + ":" + port + "/"
		response, err := client.Get(rawURL)
		if err == nil {
			response.Body.Close()
			t.Errorf("%s must be refused, got %s", rawURL, response.Status)
			continue
		}
		var violation *Violation
		if !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
			t.Errorf("%s: want a malformed-host Violation, got %v", rawURL, err)
		}
	}

	// The punycode spelling is ASCII and is judged like any other name, so
	// the refusal is of the encoding, not of internationalized hosts.
	if _, err := url.Parse("http://xn--0caa.example/"); err != nil {
		t.Fatalf("punycode host must parse: %v", err)
	}
	if _, err := hostOfURL(&url.URL{Scheme: "http", Host: "xn--0caa.example"}); err != nil {
		t.Errorf("punycode host must pass the URL gate, got %v", err)
	}
}

func TestRoundTripperForwardsCloseIdleConnections(t *testing.T) {
	// (*http.Client).CloseIdleConnections reaches the transport only through
	// this method, so the wrapper must forward it.
	closer := &idleCloseRecorder{}
	roundTripper{next: closer}.CloseIdleConnections()
	if !closer.closed {
		t.Error("CloseIdleConnections must reach the wrapped transport")
	}
	// A transport without the method is simply left alone.
	roundTripper{next: plainRoundTripper{}}.CloseIdleConnections()

	client := Policy{}.Client()
	client.CloseIdleConnections()
}

func TestStrictClientRefusesLoopbackFixtureAndAllowLoopbackFetchesIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "fixture body")
	}))
	defer server.Close()

	if _, err := (Policy{}).Client().Get(server.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("strict client must refuse the loopback fixture, got %v", err)
	}

	response, err := Policy{}.AllowLoopback().Client().Get(server.URL)
	if err != nil {
		t.Fatalf("AllowLoopback client must fetch the fixture, got %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "fixture body" {
		t.Errorf("got %q", body)
	}
}

func TestStrictAndFixtureClientsCoexist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	fixture := Policy{}.AllowLoopback().Client()
	strict := Policy{}.Client()
	if _, err := fixture.Get(server.URL); err != nil {
		t.Errorf("fixture client: %v", err)
	}
	if _, err := strict.Get(server.URL); !errors.Is(err, ErrBlocked) {
		t.Errorf("strict client sharing the process must still refuse, got %v", err)
	}
}

func TestErrBlockedSurvivesTheClientErrorChain(t *testing.T) {
	// Control-origin refusal: wrapped in net.OpError then url.Error.
	_, err := Policy{}.Client().Get("http://127.0.0.1/")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("errors.Is must see ErrBlocked through url.Error/net.OpError, got %v", err)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("client errors arrive as *url.Error, got %T", err)
	}
	var violation *Violation
	if !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
		t.Fatalf("structured violation must be reachable, got %v", err)
	}
}

func TestClientRefusesLegacyNumericURL(t *testing.T) {
	// End-to-end integration coverage: the full client path refuses a
	// legacy-numeric URL with a blocked-address Violation. This does NOT by
	// itself prove zero DNS (an ambient resolver could produce a similar
	// error); the deterministic zero-resolver proof is TestCanonicalDialAddress
	// and TestDialContextCanonicalizesLegacyNumericHostsBeforeDialing, which
	// show the token is rewritten to its literal before any dialer step.
	for _, rawURL := range []string{
		"http://2130706433/",
		"http://0x7f000001/",
		"http://[::1]/",
	} {
		_, err := Policy{}.Client().Get(rawURL)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%q: want ErrBlocked, got %v", rawURL, err)
		}
		var violation *Violation
		if !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
			t.Errorf("%q: want a blocked-address Violation, got %v", rawURL, err)
		}
	}
}

func TestRedirectToMetadataLiteralIsRefusedSynchronously(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer server.Close()

	_, err := Policy{}.AllowLoopback().Client().Get(server.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("CheckRedirect-origin refusal must match ErrBlocked, got %v", err)
	}
	var violation *Violation
	if !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
		t.Fatalf("want blocked-address violation from the hop check, got %v", err)
	}
}

func TestRedirectWithinAllowedSpaceIsFollowed(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/finish", http.StatusFound)
	})
	mux.HandleFunc("/finish", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "arrived")
	})

	response, err := Policy{}.AllowLoopback().Client().Get(server.URL + "/start")
	if err != nil {
		t.Fatalf("allowed redirect must be followed, got %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "arrived" {
		t.Errorf("got %q", body)
	}
}

func TestRedirectLoopHitsTheHopCap(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL, http.StatusFound)
	}))
	defer server.Close()

	_, err := Policy{}.AllowLoopback().Client().Get(server.URL)
	var violation *Violation
	if !errors.As(err, &violation) || violation.Reason != ReasonTooManyRedirects {
		t.Fatalf("want too-many-redirects, got %v", err)
	}

	_, err = Policy{}.AllowLoopback().MaxRedirects(0).Client().Get(server.URL)
	if !errors.As(err, &violation) || violation.Reason != ReasonTooManyRedirects {
		t.Fatalf("MaxRedirects(0) must refuse the first redirect, got %v", err)
	}
}

func redirectRequest(t *testing.T, target string, viaURLs ...string) (*http.Request, []*http.Request) {
	t.Helper()
	request, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	via := make([]*http.Request, len(viaURLs))
	for i, viaURL := range viaURLs {
		prior, err := http.NewRequest("GET", viaURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		via[i] = prior
	}
	return request, via
}

func TestCheckRedirectSchemeGates(t *testing.T) {
	check := Policy{}.CheckRedirect(nil)

	request, via := redirectRequest(t, "http://next.example/", "https://origin.example/")
	var violation *Violation
	if err := check(request, via); !errors.As(err, &violation) || violation.Reason != ReasonRedirectDowngrade {
		t.Errorf("https→http must be refused, got %v", err)
	}

	request, via = redirectRequest(t, "https://next.example/", "http://origin.example/")
	if err := check(request, via); err != nil {
		t.Errorf("http→https upgrade is fine, got %v", err)
	}

	request, via = redirectRequest(t, "ftp://next.example/", "https://origin.example/")
	if err := check(request, via); !errors.As(err, &violation) || violation.Reason != ReasonScheme {
		t.Errorf("non-http(s) schemes must be refused, got %v", err)
	}
}

func TestCheckRedirectHostGates(t *testing.T) {
	check := Policy{}.CheckRedirect(nil)
	var violation *Violation

	request, via := redirectRequest(t, "https://10.0.0.1/", "https://origin.example/")
	if err := check(request, via); !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
		t.Errorf("literal blocked hop host, got %v", err)
	}

	request, via = redirectRequest(t, "https://2130706433/", "https://origin.example/")
	if err := check(request, via); !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
		t.Errorf("legacy numeric hop host must be classified, got %v", err)
	}

	request, via = redirectRequest(t, "https://93.184.216.34./", "https://origin.example/")
	if err := check(request, via); !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
		t.Errorf("malformed hop host, got %v", err)
	}

	// Named hosts pass here: their addresses are judged at dial time.
	request, via = redirectRequest(t, "https://next.example/", "https://origin.example/")
	if err := check(request, via); err != nil {
		t.Errorf("named hop host passes to dial-time enforcement, got %v", err)
	}
}

func TestCheckRedirectRunsCallerFirstThenValidatesFinalRequest(t *testing.T) {
	// The caller callback runs first; a non-nil result stops the follow and
	// is returned unchanged, so the policy never has to validate a request
	// that will not be sent.
	custom := errors.New("caller policy")
	calls := 0
	refuse := Policy{}.CheckRedirect(func(_ *http.Request, _ []*http.Request) error {
		calls++
		return custom
	})
	request, via := redirectRequest(t, "https://10.0.0.1/", "https://origin.example/")
	if err := refuse(request, via); !errors.Is(err, custom) {
		t.Errorf("caller refusal must short-circuit and propagate, got %v", err)
	}
	if calls != 1 {
		t.Errorf("caller ran %d times", calls)
	}

	// http.ErrUseLastResponse from the caller stops the follow and is
	// returned verbatim so the client yields the last response.
	stop := Policy{}.CheckRedirect(func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	})
	request, via = redirectRequest(t, "https://10.0.0.1/", "https://origin.example/")
	if err := stop(request, via); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("ErrUseLastResponse must pass through unchanged, got %v", err)
	}

	// When the caller approves (nil), the policy validates the request the
	// caller left behind — a mutation to a blocked host is still caught.
	mutate := Policy{}.CheckRedirect(func(req *http.Request, _ []*http.Request) error {
		req.URL.Host = "10.0.0.1"
		return nil
	})
	request, via = redirectRequest(t, "https://next.example/", "https://origin.example/")
	var violation *Violation
	if err := mutate(request, via); !errors.As(err, &violation) || violation.Reason != ReasonBlockedAddr {
		t.Errorf("policy must validate the caller-mutated request, got %v", err)
	}

	// Caller approves a benign redirect: gates pass, no error.
	approve := Policy{}.CheckRedirect(func(_ *http.Request, _ []*http.Request) error { return nil })
	request, via = redirectRequest(t, "https://next.example/", "https://origin.example/")
	if err := approve(request, via); err != nil {
		t.Errorf("approved benign redirect, got %v", err)
	}
}

func TestCheckRedirectCallbackCannotHideAnHTTPSOrigin(t *testing.T) {
	// The source scheme is snapshotted before the callback, so a callback
	// that rewrites the https origin to http (to disguise a downgrade) cannot
	// slip an https→http redirect to a named host past the gate.
	erase := Policy{}.CheckRedirect(func(_ *http.Request, via []*http.Request) error {
		via[len(via)-1].URL.Scheme = "http"
		return nil
	})
	request, via := redirectRequest(t, "http://next.example/", "https://origin.example/")
	var violation *Violation
	if err := erase(request, via); !errors.As(err, &violation) || violation.Reason != ReasonRedirectDowngrade {
		t.Errorf("downgrade must be detected from the pre-callback source scheme, got %v", err)
	}
}

func TestCheckRedirectFirstHopHasNoPriorScheme(t *testing.T) {
	check := Policy{}.CheckRedirect(nil)
	// Empty via (no prior hop): no downgrade can be asserted, http target is
	// fine on its own.
	request, _ := redirectRequest(t, "http://next.example/")
	if err := check(request, nil); err != nil {
		t.Errorf("first hop http with no prior scheme is allowed, got %v", err)
	}
	// A prior hop whose URL is nil contributes no source scheme.
	request, _ = redirectRequest(t, "http://next.example/")
	via := []*http.Request{{}}
	if err := check(request, via); err != nil {
		t.Errorf("nil prior URL yields no downgrade, got %v", err)
	}
}

func TestCheckRedirectFailsClosedOnNilURL(t *testing.T) {
	// A callback that nils out the target URL must not panic the gate.
	nilOut := Policy{}.CheckRedirect(func(req *http.Request, _ []*http.Request) error {
		req.URL = nil
		return nil
	})
	request, via := redirectRequest(t, "https://next.example/", "https://origin.example/")
	var violation *Violation
	if err := nilOut(request, via); !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
		t.Errorf("nil target URL must fail closed, got %v", err)
	}
	// Defense in depth: a nil request itself fails closed rather than panicking,
	// even though net/http never produces one.
	nilReqCheck := Policy{}.CheckRedirect(nil)
	if err := nilReqCheck(nil, via); !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
		t.Errorf("nil request must fail closed, got %v", err)
	}
}

func TestCheckRedirectHopCapCountsVia(t *testing.T) {
	check := Policy{}.MaxRedirects(2).CheckRedirect(nil)
	request, via := redirectRequest(t, "https://next.example/",
		"https://a.example/", "https://b.example/")
	if err := check(request, via); err != nil {
		t.Errorf("second redirect within MaxRedirects(2), got %v", err)
	}
	request, via = redirectRequest(t, "https://next.example/",
		"https://a.example/", "https://b.example/", "https://c.example/")
	var violation *Violation
	if err := check(request, via); !errors.As(err, &violation) || violation.Reason != ReasonTooManyRedirects {
		t.Errorf("third redirect must be refused, got %v", err)
	}
}
