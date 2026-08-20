package surfguard

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The generated tables must match the checked-in IANA snapshots exactly —
// same provenance the Ruby constants are generated from, so both
// implementations share one policy source.

func snapshotPrefixes(t *testing.T, name string) []netip.Prefix {
	t.Helper()
	// testdata/iana mirrors the repo-root script/iana snapshots (the shared
	// generation source), kept in sync by TestIANASnapshotMirrorMatchesParent.
	raw, err := os.ReadFile(filepath.Join("testdata", "iana", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		SchemaVersion int      `json:"schema_version"`
		Registry      string   `json:"registry"`
		Prefixes      []string `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.Registry != name {
		t.Fatalf("%s: unexpected snapshot header %+v", name, snapshot)
	}
	prefixes := make([]netip.Prefix, len(snapshot.Prefixes))
	for i, cidr := range snapshot.Prefixes {
		prefixes[i] = netip.MustParsePrefix(cidr)
	}
	return prefixes
}

func TestGeneratedTablesMatchTheSnapshots(t *testing.T) {
	tables := map[string][]netip.Prefix{
		"ipv6_allocated":   ianaAllocatedIPv6Unicast,
		"ipv4_special_use": ianaSpecialUseIPv4,
		"ipv6_special_use": ianaSpecialUseIPv6,
	}
	for name, table := range tables {
		expected := snapshotPrefixes(t, name)
		if len(table) != len(expected) {
			t.Errorf("%s: table has %d prefixes, snapshot has %d", name, len(table), len(expected))
			continue
		}
		for i := range expected {
			if table[i] != expected[i] {
				t.Errorf("%s[%d]: table %s, snapshot %s", name, i, table[i], expected[i])
			}
		}
	}
}

func TestSnapshotFamiliesAreCoherent(t *testing.T) {
	for _, prefix := range ianaAllocatedIPv6Unicast {
		if prefix.Addr().Is4() {
			t.Errorf("allocated-unicast table contains an IPv4 prefix: %s", prefix)
		}
	}
	for _, prefix := range ianaSpecialUseIPv4 {
		if !prefix.Addr().Is4() {
			t.Errorf("IPv4 special-use table contains a non-IPv4 prefix: %s", prefix)
		}
	}
	for _, prefix := range ianaSpecialUseIPv6 {
		if prefix.Addr().Is4() {
			t.Errorf("IPv6 special-use table contains an IPv4 prefix: %s", prefix)
		}
	}
}

func TestAllocatedUnicastCoversTheCorpusPublicAddresses(t *testing.T) {
	for _, text := range []string{"2606:2800:220:1:248:1893:25c8:1946", "2620:4f:8000::1"} {
		if !containsAny(ianaAllocatedIPv6Unicast, netip.MustParseAddr(text)) {
			t.Errorf("%s must sit inside an allocated prefix", text)
		}
	}
}
