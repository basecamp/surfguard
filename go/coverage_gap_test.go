package surfguard

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
)

func TestDenyAppliesToTransitionEmbeddedIPv4(t *testing.T) {
	policy := Policy{}.Deny(netip.MustParsePrefix("11.0.0.0/8"))
	if !policy.Blocked(netip.MustParseAddr("64:ff9b::b00:1")) {
		t.Error("a deny must reach NAT64-WKP-embedded IPv4 (wraps 11.0.0.1)")
	}
	if !policy.Blocked(netip.MustParseAddr("::ffff:0:b00:1")) {
		t.Error("a deny must reach SIIT-embedded IPv4")
	}
	if Blocked(netip.MustParseAddr("64:ff9b::b00:1")) {
		t.Error("without the deny, WKP-wrapped 11.0.0.1 is public")
	}
}

func TestBareHexPrefixIsAHostnameNotANumericShape(t *testing.T) {
	// "0x" has no hex digits: not legacy-shaped, and LDH admits it as a
	// label, so it goes to DNS like any other name.
	if kind, _ := classifyHost("0x"); kind != hostName {
		t.Errorf("classifyHost(0x) = %v", kind)
	}
	if kind, _ := classifyHost("0x.example"); kind != hostName {
		t.Errorf("classifyHost(0x.example) = %v", kind)
	}
}

func TestDefaultResolverIsUsedWhenNoneIsInjected(t *testing.T) {
	if (Policy{}).lookup() != net.DefaultResolver {
		t.Error("nil resolver must fall back to net.DefaultResolver")
	}
	custom := &fakeResolver{}
	if (Policy{}).WithResolver(custom).lookup() != Resolver(custom) {
		t.Error("injected resolver must win")
	}
	// A nil resolver (explicit or default) restores net.DefaultResolver.
	if (Policy{}).WithResolver(custom).WithResolver(nil).lookup() != net.DefaultResolver {
		t.Error("WithResolver(nil) must restore the default resolver")
	}
}

func TestCheckRedirectRefusesHandCraftedHostileURLs(t *testing.T) {
	// url.Parse refuses IPvFuture and zoned hosts itself, so these can only
	// arrive via hand-constructed url.URL values; the redirect gate still
	// fails them closed.
	check := Policy{}.CheckRedirect(nil)
	via := []*http.Request{{URL: &url.URL{Scheme: "https", Host: "origin.example"}}}

	ipvFuture := &http.Request{URL: &url.URL{Scheme: "https", Host: "[v1.fe]"}}
	var violation *Violation
	if err := check(ipvFuture, via); !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
		t.Errorf("IPvFuture hop host, got %v", err)
	}

	zoned := &http.Request{URL: &url.URL{Scheme: "https", Host: "fe80::1%eth0"}}
	if err := check(zoned, via); !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
		t.Errorf("zoned hop host, got %v", err)
	}

	empty := &http.Request{URL: &url.URL{Scheme: "https", Host: ""}}
	if err := check(empty, via); !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
		t.Errorf("empty hop host, got %v", err)
	}
}
