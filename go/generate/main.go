// Command generate renders go/policy_iana.go from the IANA registry
// snapshots mirrored under go/testdata/iana — a checked-in copy of the
// repo-root script/iana snapshots the Ruby implementation also generates
// from (the two mirrors are kept identical by a drift test), so the module
// generates self-contained while the policy source of truth stays shared.
//
// Run from the go/ module directory (go generate does this):
//
//	go run ./generate            # rewrite policy_iana.go
//	go run ./generate -check     # fail if policy_iana.go is stale (CI)
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/netip"
	"os"
	"path/filepath"
)

type snapshot struct {
	SchemaVersion int      `json:"schema_version"`
	Registry      string   `json:"registry"`
	Prefixes      []string `json:"prefixes"`
}

type region struct {
	constant string
	file     string
	comments []string
}

var regions = []region{
	{
		constant: "ianaAllocatedIPv6Unicast",
		file:     "ipv6_allocated",
		comments: []string{
			"Generated from IANA IPv6 Global Unicast Status=ALLOCATED rows.",
			"Source provenance is checked in under script/iana.",
		},
	},
	{
		constant: "ianaSpecialUseIPv4",
		file:     "ipv4_special_use",
		comments: []string{
			"Every prefix in the checked-in IANA IPv4 special-purpose snapshot.",
		},
	},
	{
		constant: "ianaSpecialUseIPv6",
		file:     "ipv6_special_use",
		comments: []string{
			"Every prefix in the checked-in IANA IPv6 special-purpose snapshot.",
		},
	},
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(out)
	check := flags.Bool("check", false, "verify policy_iana.go matches the snapshots without rewriting it")
	snapshotDir := flags.String("snapshots", filepath.Join("testdata", "iana"), "directory holding the IANA snapshot JSON files")
	target := flags.String("target", "policy_iana.go", "generated file path")
	if err := flags.Parse(args); err != nil {
		return err
	}

	generated, err := render(*snapshotDir)
	if err != nil {
		return err
	}
	if *check {
		current, err := os.ReadFile(*target)
		if err != nil {
			return fmt.Errorf("read %s: %w", *target, err)
		}
		if !bytes.Equal(current, generated) {
			return fmt.Errorf("%s differs from the script/iana snapshots; review the snapshots, then run go generate", *target)
		}
		fmt.Fprintln(out, "generated IANA tables: ok")
		return nil
	}
	if err := os.WriteFile(*target, generated, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", *target)
	return nil
}

func render(snapshotDir string) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("// Code generated from the IANA registry snapshots in script/iana by\n")
	out.WriteString("// go/generate. DO NOT EDIT. Refresh with: go generate (verified in CI by\n")
	out.WriteString("// go run ./generate -check).\n\n")
	out.WriteString("package surfguard\n\n")
	for _, r := range regions {
		prefixes, err := loadSnapshot(filepath.Join(snapshotDir, r.file+".json"), r.file)
		if err != nil {
			return nil, err
		}
		out.WriteString(fmt.Sprintf("// iana-generator:begin %s\n", r.constant))
		for _, comment := range r.comments {
			out.WriteString("// " + comment + "\n")
		}
		out.WriteString(fmt.Sprintf("var %s = mustPrefixes(\n", r.constant))
		line := "\t"
		for _, cidr := range prefixes {
			word := fmt.Sprintf("%q,", cidr)
			if len(line) > 1 && len(line)+len(word)+1 > 76 {
				out.WriteString(line + "\n")
				line = "\t"
			}
			if len(line) > 1 {
				line += " "
			}
			line += word
		}
		if line != "\t" {
			out.WriteString(line + "\n")
		}
		out.WriteString(")\n")
		out.WriteString(fmt.Sprintf("// iana-generator:end %s\n\n", r.constant))
	}
	return format.Source(out.Bytes())
}

func loadSnapshot(path, registry string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if snap.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s: unsupported schema_version %d", path, snap.SchemaVersion)
	}
	if snap.Registry != registry {
		return nil, fmt.Errorf("%s: registry %q, expected %q", path, snap.Registry, registry)
	}
	if len(snap.Prefixes) == 0 {
		return nil, fmt.Errorf("%s: empty prefix list", path)
	}
	for _, cidr := range snap.Prefixes {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return snap.Prefixes, nil
}
