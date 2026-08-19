package surfguard

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The module reads its shared data from testdata/ mirrors so it stays
// self-contained when distributed (a module zip contains only files beneath
// go/). These tests prove the mirrors are byte-identical to the repo-root
// sources of truth. They run only in the full repository checkout; on a
// downloaded module the parent directories are absent and the test skips —
// the mirror is authoritative there.

// assertMirror enumerates every JSON file under parentDir and byte-compares
// it to its counterpart under mirrorDir, then checks the reverse direction so
// neither an added parent file nor a stale mirror file can slip through. It
// does not rely on a hardcoded file list: a new registry or corpus file is
// covered automatically.
func assertMirror(t *testing.T, parentDir, mirrorDir string) {
	t.Helper()
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		t.Skipf("parent %s absent (distributed module); mirror is authoritative", parentDir)
	}
	parentFiles := jsonEntries(t, parentDir)
	mirrorFiles := jsonEntries(t, mirrorDir)

	for name := range parentFiles {
		if !mirrorFiles[name] {
			t.Errorf("%s exists under %s but is not mirrored under %s", name, parentDir, mirrorDir)
			continue
		}
		parent, err := os.ReadFile(filepath.Join(parentDir, name))
		if err != nil {
			t.Errorf("read parent %s: %v", name, err)
			continue
		}
		mirror, err := os.ReadFile(filepath.Join(mirrorDir, name))
		if err != nil {
			t.Errorf("read mirror %s: %v", name, err)
			continue
		}
		if !bytes.Equal(parent, mirror) {
			t.Errorf("%s drifted from %s: re-copy before committing",
				filepath.Join(mirrorDir, name), filepath.Join(parentDir, name))
		}
	}
	for name := range mirrorFiles {
		if !parentFiles[name] {
			t.Errorf("%s exists under %s but not under the source of truth %s", name, mirrorDir, parentDir)
		}
	}
}

func jsonEntries(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names[entry.Name()] = true
		}
	}
	if len(names) == 0 {
		t.Fatalf("no JSON files under %s", dir)
	}
	return names
}

func TestConformanceMirrorMatchesParent(t *testing.T) {
	assertMirror(t, filepath.Join("..", "conformance"), filepath.Join("testdata", "conformance"))
}

func TestIANASnapshotMirrorMatchesParent(t *testing.T) {
	assertMirror(t, filepath.Join("..", "script", "iana"), filepath.Join("testdata", "iana"))
}
