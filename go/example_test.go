package surfguard_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	surfguard "github.com/basecamp/surfguard/go"
)

// The drop-in client: every connection is judged at dial time, every
// redirect hop is re-validated, proxying is disabled.
func ExampleClient() {
	client := surfguard.Client()
	_, err := client.Get("http://169.254.169.254/latest/meta-data/")
	fmt.Println(errors.Is(err, surfguard.ErrBlocked))
	// Output: true
}

// Advertised or discovered values get the stricter policy; the consumer
// chooses it, never the target.
func ExamplePolicy_IANASpecialUse() {
	policy := surfguard.Policy{}.IANASpecialUse()
	client := policy.Client()
	_, err := client.Get("http://[64:ff9b::5db8:d822]/") // NAT64 WKP, even wrapping a public IPv4
	fmt.Println(errors.Is(err, surfguard.ErrBlocked))
	// Output: true
}

// Classify-then-pin: resolve once, keep the hostname for Host/SNI, and
// connect to the returned addresses yourself.
func ExamplePolicy_ResolvePublicAddrs() {
	addrs, err := surfguard.ResolvePublicAddrs(context.Background(), "93.184.216.34")
	if err != nil {
		var unresolvable *surfguard.UnresolvableError
		if errors.As(err, &unresolvable) {
			// Retry later: the host may resolve next time.
		}
		return
	}
	for _, addr := range addrs {
		fmt.Println(addr) // dial these, in order
	}
	// Output: 93.184.216.34
}

// Fixture mode: a test binary talks to httptest loopback servers with a
// policy that stays strict for everything else.
func ExamplePolicy_AllowLoopback() {
	fixture := surfguard.Policy{}.AllowLoopback()
	fmt.Println(fixture.BlockedHost("127.0.0.1"))
	fmt.Println(fixture.BlockedHost("169.254.169.254"))
	// Output:
	// false
	// true
}

// Wiring the enforcement layer into an existing transport by hand.
func ExamplePolicy_DialContext() {
	policy := surfguard.Policy{}
	transport := &http.Transport{
		Proxy:       nil, // never proxy: the proxy address would be judged instead of the target
		DialContext: policy.DialContext,
	}
	client := &http.Client{Transport: transport, CheckRedirect: policy.CheckRedirect(nil)}
	_, err := client.Get("http://127.0.0.1/")
	fmt.Println(errors.Is(err, surfguard.ErrBlocked))
	// Output: true
}
