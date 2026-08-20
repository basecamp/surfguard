package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotsDir points at the mirror the generator reads by default, relative
// to this test's working directory (the generate/ package dir).
func snapshotsDir() string { return filepath.Join("..", "testdata", "iana") }

func TestRenderMatchesTheCommittedTables(t *testing.T) {
	got, err := render(snapshotsDir())
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join("..", "policy_iana.go"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(committed) {
		t.Error("render output differs from the committed policy_iana.go; run go generate")
	}
	// Spot-check structure: the marker convention shared with the Ruby
	// generator, and one known prefix from each region.
	text := string(got)
	for _, want := range []string{
		"// iana-generator:begin ianaAllocatedIPv6Unicast",
		"// iana-generator:end ianaSpecialUseIPv6",
		"\"2001::/23\"", "\"100.64.0.0/10\"", "\"64:ff9b::/96\"",
		"DO NOT EDIT",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated source missing %q", want)
		}
	}
}

func TestLoadSnapshotRejectsMalformedInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	cases := []struct{ name, body, registry, wantErr string }{
		{"not-json.json", "{bad", "x", "invalid character"},
		{"wrong-schema.json", `{"schema_version":2,"registry":"x","prefixes":["10.0.0.0/8"]}`, "x", "schema_version"},
		{"wrong-registry.json", `{"schema_version":1,"registry":"y","prefixes":["10.0.0.0/8"]}`, "x", "registry"},
		{"empty.json", `{"schema_version":1,"registry":"x","prefixes":[]}`, "x", "empty"},
		{"bad-prefix.json", `{"schema_version":1,"registry":"x","prefixes":["not-a-prefix"]}`, "x", "not-a-prefix"},
	}
	for _, c := range cases {
		path := write(c.name, c.body)
		_, err := loadSnapshot(path, c.registry)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %v; want containing %q", c.name, err, c.wantErr)
		}
	}
	if _, err := loadSnapshot(filepath.Join(dir, "missing.json"), "x"); err == nil {
		t.Error("missing file must error")
	}

	good := write("good.json", `{"schema_version":1,"registry":"ok","prefixes":["10.0.0.0/8","fc00::/7"]}`)
	prefixes, err := loadSnapshot(good, "ok")
	if err != nil || len(prefixes) != 2 {
		t.Errorf("valid snapshot: %v, %v", prefixes, err)
	}
}

func TestRenderFailsOnMissingSnapshotDir(t *testing.T) {
	if _, err := render(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("render must fail when a snapshot file is missing")
	}
}

func TestRunCheckAndWrite(t *testing.T) {
	var out strings.Builder
	// -check against the committed target passes.
	if err := run([]string{"-check", "-snapshots", snapshotsDir(), "-target", filepath.Join("..", "policy_iana.go")}, &out); err != nil {
		t.Errorf("check mode: %v", err)
	}
	if !strings.Contains(out.String(), "generated IANA tables: ok") {
		t.Errorf("check mode output: %q", out.String())
	}

	// Write mode produces a file identical to the committed one.
	target := filepath.Join(t.TempDir(), "out.go")
	out.Reset()
	if err := run([]string{"-snapshots", snapshotsDir(), "-target", target}, &out); err != nil {
		t.Fatalf("write mode: %v", err)
	}
	written, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	committed, _ := os.ReadFile(filepath.Join("..", "policy_iana.go"))
	if string(written) != string(committed) {
		t.Error("written output differs from the committed policy_iana.go")
	}

	// -check against a stale target fails.
	stale := filepath.Join(t.TempDir(), "stale.go")
	os.WriteFile(stale, []byte("package surfguard\n"), 0o644)
	if err := run([]string{"-check", "-snapshots", snapshotsDir(), "-target", stale}, &out); err == nil {
		t.Error("check mode must fail on a stale target")
	}
}

func TestRunErrors(t *testing.T) {
	var out strings.Builder
	// Bad flag.
	if err := run([]string{"-nope"}, &out); err == nil {
		t.Error("unknown flag must error")
	}
	// Missing snapshots dir.
	if err := run([]string{"-snapshots", filepath.Join(t.TempDir(), "absent")}, &out); err == nil {
		t.Error("missing snapshots dir must error")
	}
	// -check with an unreadable target.
	if err := run([]string{"-check", "-snapshots", snapshotsDir(), "-target", filepath.Join(t.TempDir(), "nope.go")}, &out); err == nil {
		t.Error("check with a missing target must error")
	}
	// Write to an unwritable path.
	if err := run([]string{"-snapshots", snapshotsDir(), "-target", filepath.Join(t.TempDir(), "no-such-dir", "x.go")}, &out); err == nil {
		t.Error("write to a missing directory must error")
	}
}
