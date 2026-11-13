package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// fakeRegistry replaces the two seams a registry sweep needs: resolving a
// project to a version, and unpacking that artifact into a directory of its own.
// Each project lays down the files it is given, so the union across separate
// directories is what the test is about.
func fakeRegistry(t *testing.T, files map[string]map[string][]string) {
	t.Helper()
	oldR, oldI := resolveOne, installFor
	t.Cleanup(func() { resolveOne, installFor = oldR, oldI })

	resolveOne = func(proj, _, _, _ string) (artifact.Resolved, error) {
		if _, ok := files[proj]; !ok {
			return artifact.Resolved{}, errors.New("no such project here")
		}
		return artifact.Resolved{Project: proj, Version: artifact.ParseVer("1.0.0")}, nil
	}
	installFor = func(r artifact.Resolved, dir, _, _ string) (bool, error) {
		for name, needed := range files[r.Project] {
			p := filepath.Join(dir, r.Project, "v1.0.0", "bin", name)
			if strings.Contains(name, ".so") {
				p = filepath.Join(dir, r.Project, "v1.0.0", "lib", name)
			}
			writeELFNeeded(t, p, needed...)
		}
		return true, nil
	}
}

// The shape this exists for: an artifact links a library that NO artifact in the
// set provides, and each is unpacked on its own because a build ORDER is not
// a coexisting set.
func TestSonamesNamesWhatNobodyProvides(t *testing.T) {
	fakeRegistry(t, map[string]map[string][]string{
		"gnu.org/glibc": {"libc.so.6": nil},
		"gnu.org/sed":   {"sed": {"libc.so.6", "libselinux.so.1"}},
		"gnu.org/tar":   {"tar": {"libc.so.6"}},
	})
	var out, errb bytes.Buffer
	if rc := runSonames([]string{"gnu.org/glibc", "gnu.org/sed", "gnu.org/tar"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d: %s", rc, errb.String())
	}
	got := out.String()
	for _, w := range []string{"3 of 3 project(s) read", "libselinux.so.1", "gnu.org/sed:sed"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
	// libc.so.6 is provided by another artifact ENTIRELY — the union across
	// separate directories is the whole point.
	if strings.Contains(got, "libc.so.6 <-") {
		t.Errorf("a soname provided by a sibling was reported missing:\n%s", got)
	}
}

// Without a libc in the set, every libc symbol reads as missing — correctly
// and uselessly. The census says `here`, and `here` is whatever was named.
func TestSonamesSaysWhenTheSetHasNoLibc(t *testing.T) {
	fakeRegistry(t, map[string]map[string][]string{
		"gnu.org/sed": {"sed": {"libc.so.6"}},
	})
	var out, errb bytes.Buffer
	if rc := runSonames([]string{"gnu.org/sed"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d: %s", rc, errb.String())
	}
	if !strings.Contains(out.String(), "is not in this set") {
		t.Errorf("the note is missing:\n%s", out.String())
	}
	// And with one, no note.
	fakeRegistry(t, map[string]map[string][]string{
		"gnu.org/glibc": {"libc.so.6": nil},
	})
	var out2, errb2 bytes.Buffer
	_ = runSonames([]string{"gnu.org/glibc"}, &out2, &errb2)
	if strings.Contains(out2.String(), "is not in this set") {
		t.Errorf("the note fired with a libc present:\n%s", out2.String())
	}
}

// A project that cannot be read is SAID, never dropped: a census that loses
// one quietly reports a smaller number for the wrong reason.
func TestSonamesSaysWhichProjectsItCouldNotRead(t *testing.T) {
	fakeRegistry(t, map[string]map[string][]string{
		"gnu.org/glibc": {"libc.so.6": nil},
	})
	var out, errb bytes.Buffer
	if rc := runSonames([]string{"gnu.org/glibc", "ghost.org"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got := out.String()
	for _, w := range []string{"1 of 2 project(s) read", "UNREAD ghost.org"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

// An install that fails is the other half of the same rule.
func TestSonamesSaysWhenAnInstallFails(t *testing.T) {
	fakeRegistry(t, map[string]map[string][]string{"gnu.org/glibc": {"libc.so.6": nil}})
	old := installFor
	installFor = func(artifact.Resolved, string, string, string) (bool, error) {
		return false, errors.New("blob truncated")
	}
	t.Cleanup(func() { installFor = old })
	var out, errb bytes.Buffer
	_ = runSonames([]string{"gnu.org/glibc"}, &out, &errb)
	if !strings.Contains(out.String(), "blob truncated") {
		t.Errorf("a failed install was swallowed:\n%s", out.String())
	}
}

func TestSonameRootsFromAFileAndTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "order.txt")
	if err := os.WriteFile(f, []byte("# a comment\n\ngnu.org/sed\nperl.org@~5.44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots, err := sonameRoots(f, []string{"gnu.org/tar"})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 3 {
		t.Fatalf("got %v", roots)
	}
	if roots["perl.org"] != "~5.44" {
		t.Errorf("the constraint was lost: %q", roots["perl.org"])
	}
	if _, err := sonameRoots("", nil); err == nil {
		t.Error("naming nothing is an error, not an empty census")
	}
	if _, err := sonameRoots(filepath.Join(dir, "absent"), nil); err == nil {
		t.Error("an unreadable list is an error")
	}
}

// --keep leaves the tree behind, which is how a person looks at what the
// census read.
func TestSonamesKeepsTheTreeWhenAsked(t *testing.T) {
	fakeRegistry(t, map[string]map[string][]string{"gnu.org/glibc": {"libc.so.6": nil}})
	keep := filepath.Join(t.TempDir(), "kept")
	var out, errb bytes.Buffer
	if rc := runSonames([]string{"--keep", keep, "gnu.org/glibc"}, &out, &errb); rc != 0 {
		t.Fatalf("rc = %d: %s", rc, errb.String())
	}
	if _, err := os.Stat(filepath.Join(keep, "gnu.org_glibc")); err != nil {
		t.Errorf("--keep left nothing: %v", err)
	}
}

func TestSonamesRefusals(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runSonames([]string{"--not-a-flag"}, &out, &errb); rc != 2 {
		t.Errorf("rc = %d for a bad flag, want 2", rc)
	}
	if rc := runSonames(nil, &out, &errb); rc != 2 {
		t.Errorf("rc = %d for no projects, want 2", rc)
	}
	// A temp directory that cannot be made: the census has nowhere to unpack.
	old := osMkdirTemp
	osMkdirTemp = func(string, string) (string, error) { return "", errors.New("read-only") }
	t.Cleanup(func() { osMkdirTemp = old })
	if rc := runSonames([]string{"gnu.org/glibc"}, &out, &errb); rc != 1 {
		t.Errorf("rc = %d, want 1", rc)
	}
}

// resolveOne asks for ONE project and must not take a dependency's version
// for it.
func TestResolveOnePicksTheProjectItWasAsked(t *testing.T) {
	old := resolveClosureFor
	t.Cleanup(func() { resolveClosureFor = old })
	resolveClosureFor = func(map[string]string, string, string) ([]artifact.Resolved, error) {
		return []artifact.Resolved{
			{Project: "gnu.org/glibc", Version: artifact.ParseVer("2.44.0")},
			{Project: "gnu.org/sed", Version: artifact.ParseVer("4.10")},
		}, nil
	}
	r, err := resolveOne("gnu.org/sed", "", "linux", "x86-64")
	if err != nil || r.Version.Raw != "4.10" {
		t.Errorf("got %v, %v", r, err)
	}
	// A closure that does not contain what was asked is an error, not the
	// first entry.
	if _, err := resolveOne("ghost.org", "", "linux", "x86-64"); err == nil {
		t.Error("a closure without the project resolved anyway")
	}
	resolveClosureFor = func(map[string]string, string, string) ([]artifact.Resolved, error) {
		return nil, errors.New("not published here")
	}
	if _, err := resolveOne("gnu.org/sed", "", "linux", "x86-64"); err == nil {
		t.Error("a resolution failure was swallowed")
	}
}

// Through run(), so the dispatch line is exercised and `bk sonames` is a
// command and not only a function. --dist too: pointing the census at
// another registry is the reason it takes the flag.
func TestSonamesThroughTheCommandAndWithADist(t *testing.T) {
	fakeRegistry(t, map[string]map[string][]string{"gnu.org/glibc": {"libc.so.6": nil}})
	old := artifact.DistBase
	t.Cleanup(func() { artifact.DistBase = old })

	code, out, errb := run2(t, "sonames", "--dist", "oci://example.invalid/x/", "gnu.org/glibc")
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errb)
	}
	if !strings.Contains(out, "1 of 1 project(s) read") {
		t.Errorf("got %q", out)
	}
	// The trailing slash comes off, like every other --dist in this command
	// set, or two callers spell the same registry two ways.
	if artifact.DistBase != "oci://example.invalid/x" {
		t.Errorf("DistBase = %q", artifact.DistBase)
	}
}
