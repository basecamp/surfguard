package surfguard

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The shared corpus under ../conformance is the drift-proof between the Ruby
// and Go implementations: every verdict in it is asserted by both test
// suites against identical inputs.

type corpusCase struct {
	Label     string            `json:"label"`
	Input     string            `json:"input"`
	Policies  map[string]string `json:"policies"`
	Canonical string            `json:"canonical"`
	Blocked   bool              `json:"blocked"`
	Note      string            `json:"note"`
}

func corpusCases(t *testing.T, name string) []corpusCase {
	t.Helper()
	// testdata/conformance is a checked-in mirror of the repo-root
	// conformance corpus, kept in sync by TestConformanceMirrorMatchesParent.
	// Reading it (not ../conformance) keeps the module self-contained: the
	// tests run against a downloaded module zip, which contains only files
	// beneath go/.
	raw, err := os.ReadFile(filepath.Join("testdata", "conformance", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		SchemaVersion int          `json:"schema_version"`
		Cases         []corpusCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.SchemaVersion != 1 {
		t.Fatalf("%s: unsupported schema_version %d", name, file.SchemaVersion)
	}
	if len(file.Cases) == 0 {
		t.Fatalf("%s: empty corpus", name)
	}
	return file.Cases
}

func corpusPolicies() map[string]Policy {
	return map[string]Policy{
		"default":          {},
		"iana_special_use": Policy{}.IANASpecialUse(),
	}
}

func TestConformanceClassification(t *testing.T) {
	for _, name := range []string{"blocked", "allowed", "boundaries"} {
		for _, c := range corpusCases(t, name) {
			addr := netip.MustParseAddr(c.Input)
			for policyName, verdict := range c.Policies {
				policy, ok := corpusPolicies()[policyName]
				if !ok {
					t.Fatalf("%s: %s: unknown policy %q", name, c.Label, policyName)
				}
				blocked := verdict == "blocked"
				if got := policy.Blocked(addr); got != blocked {
					t.Errorf("%s: %s (%s) under %s: Blocked = %v, corpus says %s",
						name, c.Label, c.Input, policyName, got, verdict)
				}
				if got := policy.BlockedHost(c.Input); got != blocked {
					t.Errorf("%s: %s (%s) under %s: BlockedHost = %v, corpus says %s",
						name, c.Label, c.Input, policyName, got, verdict)
				}
			}
		}
	}
}

func TestConformanceLegacyNumericSpellingsSkipDNSAndClassify(t *testing.T) {
	for _, c := range corpusCases(t, "legacy_numeric") {
		// A poisoned public answer models a wildcard/search-domain response:
		// if the spelling ever reached DNS, the admitted result would differ.
		resolver := &fakeResolver{wildcard: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
		policy := Policy{}.WithResolver(resolver)
		got, err := policy.ResolvePublicAddrs(context.Background(), c.Input)
		if err != nil {
			t.Errorf("%s (%s): unexpected error %v", c.Label, c.Input, err)
			continue
		}
		if len(resolver.queriedHosts()) != 0 {
			t.Errorf("%s (%s): sent to DNS: %v", c.Label, c.Input, resolver.queriedHosts())
		}
		canonical := netip.MustParseAddr(c.Canonical)
		if c.Blocked {
			if len(got) != 0 {
				t.Errorf("%s (%s): expected no admitted addresses, got %v", c.Label, c.Input, got)
			}
			if !policy.BlockedHost(c.Input) {
				t.Errorf("%s (%s): BlockedHost = false", c.Label, c.Input)
			}
		} else {
			if len(got) != 1 || got[0] != canonical {
				t.Errorf("%s (%s): expected [%s], got %v", c.Label, c.Input, canonical, got)
			}
			if policy.BlockedHost(c.Input) {
				t.Errorf("%s (%s): BlockedHost = true for admitted spelling", c.Label, c.Input)
			}
		}
		if Blocked(canonical) != c.Blocked {
			t.Errorf("%s: canonical %s verdict disagrees with corpus", c.Label, c.Canonical)
		}
	}
}

func TestConformanceMalformedNumericHostsRefusedWithoutDNS(t *testing.T) {
	for _, name := range []string{"malformed_numeric_hosts", "non_host_prefixes"} {
		for _, c := range corpusCases(t, name) {
			resolver := &fakeResolver{wildcard: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
			policy := Policy{}.WithResolver(resolver)
			_, err := policy.ResolvePublicAddrs(context.Background(), c.Input)
			var violation *Violation
			if !errors.As(err, &violation) || violation.Reason != ReasonMalformedHost {
				t.Errorf("%s: %q: expected malformed-host refusal, got %v", name, c.Input, err)
			}
			if !errors.Is(err, ErrBlocked) {
				t.Errorf("%s: %q: refusal must be in the ErrBlocked family", name, c.Input)
			}
			if len(resolver.queriedHosts()) != 0 {
				t.Errorf("%s: %q: sent to DNS: %v", name, c.Input, resolver.queriedHosts())
			}
			if !policy.BlockedHost(c.Input) {
				t.Errorf("%s: %q: BlockedHost = false", name, c.Input)
			}
		}
	}
}

func TestConformanceFullWidthPrefixesRemainValidLiterals(t *testing.T) {
	// The counterpart to non_host_prefixes: full-width spellings denote
	// exactly one host address and stay valid.
	for host, want := range map[string]string{
		"93.184.216.34/32":                       "93.184.216.34",
		"2606:2800:220:1:248:1893:25c8:1946/128": "2606:2800:220:1:248:1893:25c8:1946",
	} {
		resolver := &fakeResolver{}
		got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), host)
		if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr(want) {
			t.Errorf("%q: got %v, %v; want [%s]", host, got, err, want)
		}
		if len(resolver.queriedHosts()) != 0 {
			t.Errorf("%q: sent to DNS", host)
		}
	}
}

func TestConformanceNumericLabelHostnamesStillReachDNS(t *testing.T) {
	public := netip.MustParseAddr("93.184.216.34")
	for _, c := range corpusCases(t, "dns_hostnames") {
		resolver := &fakeResolver{wildcard: []netip.Addr{public}}
		got, err := Policy{}.WithResolver(resolver).ResolvePublicAddrs(context.Background(), c.Input)
		if err != nil || len(got) != 1 || got[0] != public {
			t.Errorf("%q: got %v, %v; want the resolver answer", c.Input, got, err)
		}
		if hosts := resolver.queriedHosts(); len(hosts) != 1 || hosts[0] != c.Input {
			t.Errorf("%q: expected exactly one queried host, got %v", c.Input, hosts)
		}
	}
}
