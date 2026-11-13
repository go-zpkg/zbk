package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
)

// checkAdvisories is what turns a run lost on its fortieth bottle into a usage
// error, so each refusal is tested at the shape a factory would meet it in.
func TestCheckAdvisories(t *testing.T) {
	t.Run("a tree that is usable", func(t *testing.T) {
		dir := advisoryTree(t, map[string]string{
			"curl.se":            file("curl.se", detected),
			"x.org/protocol/xcb": file("x.org/protocol/xcb", detected),
		})
		n, err := checkAdvisories(dir)
		if err != nil {
			t.Fatalf("checkAdvisories: %v", err)
		}
		// The COUNT, because a factory prints it: a tree that was found and
		// read is distinguishable from one that was found empty only by a
		// number.
		if n != 2 {
			t.Errorf("n = %d, want 2", n)
		}
	})

	t.Run("no tree at all", func(t *testing.T) {
		// Not an error, and reads nothing: a factory with no advisory tree
		// attaches no document, which is the honest state.
		n, err := checkAdvisories("")
		if n != 0 || err != nil {
			t.Errorf("n = %d, err = %v", n, err)
		}
	})

	t.Run("an empty tree", func(t *testing.T) {
		// ⛔ AN ERROR. A run that was TOLD where the records are and found
		// none would publish every bottle with no document and look correct.
		_, err := checkAdvisories(t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "the tree moved") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a path that is not there", func(t *testing.T) {
		_, err := checkAdvisories(filepath.Join(t.TempDir(), "nope"))
		if err == nil || !strings.Contains(err.Error(), "no advisories.yaml under") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a record that does not parse", func(t *testing.T) {
		dir := advisoryTree(t, map[string]string{
			"curl.se": file("curl.se", "  - id: CVE-1\n    events:\n      - type: detection\n"),
		})
		_, err := checkAdvisories(dir)
		if err == nil || !strings.Contains(err.Error(), "has no timestamp") {
			t.Fatalf("err = %v", err)
		}
		// Named, so the operator knows which file to open.
		if !strings.Contains(err.Error(), "curl.se") {
			t.Errorf("err %q does not name the file", err)
		}
	})

	t.Run("a record naming another project", func(t *testing.T) {
		dir := advisoryTree(t, map[string]string{"curl.se": file("openssl.org", detected)})
		_, err := checkAdvisories(dir)
		if err == nil || !strings.Contains(err.Error(), `says project "openssl.org"`) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a record that cannot be read", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read an unreadable file")
		}
		dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
		p := filepath.Join(dir, "curl.se", advisoryFile)
		if err := os.Chmod(p, 0o000); err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
		// NOT folded into "absent": a record we cannot open must stop the run
		// rather than let every bottle publish with no document.
		_, err := checkAdvisories(dir)
		if err == nil || !strings.Contains(err.Error(), "advisories:") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("a tree the walk cannot descend", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read an unreadable directory")
		}
		dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
		sub := filepath.Join(dir, "curl.se")
		if err := os.Chmod(sub, 0o000); err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
		_, err := checkAdvisories(dir)
		if err == nil {
			t.Fatal("a walk error read as an empty tree")
		}
		// And it is NOT the empty-tree message, which is the failure this
		// case exists to tell apart — both would otherwise stop the run with
		// the operator looking in the wrong place.
		if strings.Contains(err.Error(), "the tree moved") {
			t.Errorf("a walk error was reported as an empty tree: %v", err)
		}
	})
}

// `bk factory --advisories` is a declared flag, and a broken tree stops the
// run before a single build starts.
//
// Both an undeclared flag and a refused tree exit non-zero, so the exit code
// alone proves nothing; the complaint is what distinguishes them.
func TestFactoryRefusesABrokenAdvisoryTreeUpFront(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", "  - id: CVE-1\n    events: []\n")})
	rc, out, errb := run2(t, "factory", "--platform", "linux/x86-64",
		"--advisories", dir, "--pantry", t.TempDir(), "--to", "oci://example.invalid/x")
	if rc == 0 {
		t.Fatalf("a broken advisory tree did not stop the factory (out %q)", out)
	}
	if strings.Contains(errb, "not defined") {
		t.Fatalf("--advisories is not a declared flag: %q", errb)
	}
	// ⛔ NOT the usage line. The first version of this test omitted
	// --platform, so the run exited non-zero before reaching the advisory
	// check at all — the exit code said "refused" and meant "misused". Only
	// asserting the MESSAGE caught it.
	if strings.Contains(errb, "usage: bk factory") {
		t.Fatalf("the factory never reached the advisory check: %q", errb)
	}
	if !strings.Contains(errb, "has no events") {
		t.Errorf("want the record's own complaint, got %q", errb)
	}
	// Nothing was built or published: the refusal is BEFORE the loop.
	if strings.Contains(out, "✅") {
		t.Errorf("something was published anyway:\n%s", out)
	}
}

// ⛔ THE TREE REACHES THE PUBLISH. This is the feature, and a mutation that
// replaced `f.advisories` with "" on the way to publishBottle survived the
// whole suite before this existed: every other test asserted what was built
// and where it went, and none asserted what the bottle would CARRY.
func TestFactoryHandsTheAdvisoryTreeToEveryPublish(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, h.pantry, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	tree := advisoryTree(t, map[string]string{"app.org": file("app.org", detected)})

	if code := h.run(t, "--recipes", "app.org", "--to", "oci://example.test/pkgs", "--advisories", tree); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if len(h.published) == 0 {
		t.Fatal("nothing was published, so nothing was asserted")
	}
	// EVERY publish, including the closure dependency that has no record of
	// its own: the tree is where to look, not a per-project switch.
	for _, p := range h.published {
		if p.advisories != tree {
			t.Errorf("%s published with advisories %q, want %q", p.project, p.advisories, tree)
		}
	}
}

// And a MIRRORED bottle too. We did not build it, but we are the one
// republishing it signed, and what is known about a package is not a property
// of who compiled it.
func TestFactoryHandsTheAdvisoryTreeToAMirroredPublish(t *testing.T) {
	h := newFactoryHarness(t)
	tree := advisoryTree(t, map[string]string{"lib.org": file("lib.org", detected)})
	prevDown, prevVers := factoryDownload, factoryUpstreamVersions
	t.Cleanup(func() { factoryDownload, factoryUpstreamVersions = prevDown, prevVers })
	factoryUpstreamVersions = func(string, string, string) ([]bottle.Ver, error) {
		return []bottle.Ver{bottle.ParseVer("1.0")}, nil
	}
	factoryDownload = func(string, string, string, string) ([]byte, string, error) {
		return []byte("bottle"), bottle.ExtTarXz, nil
	}

	code := h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
		"--mirror-from", "https://dist.example.test", "--advisories", tree)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if len(h.published) == 0 {
		t.Fatal("nothing was mirrored, so nothing was asserted")
	}
	for _, p := range h.published {
		if p.advisories != tree {
			t.Errorf("mirrored %s published with advisories %q, want %q", p.project, p.advisories, tree)
		}
	}
}

// ⛔ Nothing the factory suite runs may write into the repository.
//
// Four of the factory's flags default to a path relative to the CURRENT
// directory, which under `go test` is cmd/bk. Three of them had been given
// temporary paths in the harness and `--bottles` had not, so a mirror test
// staged `cmd/bk/dist/lib.org/linux/x86-64/v1.0.tar.xz` and `git add -A`
// committed it. This is the positive control: it runs the path that stages a
// bottle and then asserts the repository is still clean.
func TestTheFactorySuiteCannotWriteIntoTheRepository(t *testing.T) {
	for _, p := range []string{"dist", "tests.txt", "failures.txt", "failures-detail.txt"} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("cmd/bk/%s exists — a factory test wrote into the repository", p)
		}
	}
	h := newFactoryHarness(t)
	prevDown, prevVers := factoryDownload, factoryUpstreamVersions
	t.Cleanup(func() { factoryDownload, factoryUpstreamVersions = prevDown, prevVers })
	factoryUpstreamVersions = func(string, string, string) ([]bottle.Ver, error) {
		return []bottle.Ver{bottle.ParseVer("1.0")}, nil
	}
	factoryDownload = func(string, string, string, string) ([]byte, string, error) {
		return []byte("bottle"), bottle.ExtTarXz, nil
	}
	if code := h.run(t, "--recipes", "lib.org", "--to", "oci://example.test/pkgs",
		"--mirror-from", "https://dist.example.test"); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	// It really did stage something, or this control proves nothing.
	if len(h.published) == 0 {
		t.Fatal("nothing was mirrored, so nothing was staged and nothing is proven")
	}
	for _, p := range []string{"dist", "tests.txt", "failures.txt", "failures-detail.txt"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("cmd/bk/%s was created by this run", p)
		}
	}
}

// A usable tree is announced with its COUNT, before anything else happens.
//
// Without the count, a run that loaded the tree and one that was pointed at
// the wrong path print the same thing — and this fleet has already published a
// zero that meant "could not read". The run here still fails afterwards (no
// recipes.txt), which is the point: the line comes out BEFORE the pantry is
// touched.
func TestFactoryAnnouncesTheAdvisoryTreeItLoaded(t *testing.T) {
	dir := advisoryTree(t, map[string]string{"curl.se": file("curl.se", detected)})
	_, out, _ := run2(t, "factory", "--platform", "linux/x86-64",
		"--advisories", dir, "--pantry", t.TempDir(), "--to", "oci://example.invalid/x")
	if !strings.Contains(out, "advisories: 1 project(s) with records") {
		t.Errorf("want the count on stdout:\n%s", out)
	}
	// And the path, so "which tree" is answerable from the log alone.
	if !strings.Contains(out, dir) {
		t.Errorf("want the tree's path on stdout:\n%s", out)
	}
}
