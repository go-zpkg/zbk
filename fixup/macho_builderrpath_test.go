package fixup

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// go-zpkg/bk#395: every darwin artifact carried an absolute LC_RPATH into the
// builder's store ($ZPKG_DIR as the build ran). These tests derive that store
// from the test's own ZpkgDir, as the build does, and never name a runner path.

func rpathsOf(t *testing.T, path string) []string {
	t.Helper()
	r, err := machoRpaths(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The before/after the issue asks for, on a file for which the existing
// relativising cannot help (it sits OUTSIDE the store, so a relative spelling
// would climb out of the tree): the fallback is present before, gone after, and
// everything else is untouched and in order.
func TestBuilderStoreRpathIsPresentBeforeAndGoneAfter(t *testing.T) {
	store := filepath.Join(t.TempDir(), ".pkgx")
	exe := filepath.Join(t.TempDir(), "lib", "libfoo.dylib")
	placePad(t, exe, 256,
		machoCmd{lcRpath, "@loader_path/../lib"},
		machoCmd{lcRpath, store},
		machoCmd{lcRpath, "/usr/local/lib"},
		machoCmd{lcRpath, filepath.Join(store, "zlib.net", "v1.3.1", "lib")},
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)
	// BEFORE: the guard sees the fallback. This is what makes the zero below mean
	// something — the same check, the same file, a different answer.
	if err := checkNoBuilderRpath(exe, store); !errors.Is(err, ErrBuilderRpath) {
		t.Fatalf("before: err = %v, want ErrBuilderRpath", err)
	}
	if err := rewriteMacho(exe, Options{Prefix: filepath.Dir(filepath.Dir(exe)), Platform: "darwin", ZpkgDir: store}); err != nil {
		t.Fatal(err)
	}
	if err := checkNoBuilderRpath(exe, store); err != nil {
		t.Fatalf("after: %v", err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"@loader_path/../lib", "/usr/local/lib", "/usr/lib/libSystem.B.dylib"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("strings after = %q, want %q (order kept, outside-store rpath kept)", got, want)
	}
	// The slice still parses with its counts consistent.
	if _, err := machoInfo2(exe); err != nil {
		t.Fatal(err)
	}
}

func machoInfo2(path string) (int, error) {
	_, sl, err := machoInfo(path)
	return len(sl), err
}

// The store is whatever the build says it is: the same file is clean under a
// different store and dirty under its own.
func TestTheStoreRootIsDerivedNotLiteral(t *testing.T) {
	storeA := filepath.Join(t.TempDir(), "storeA")
	storeB := filepath.Join(t.TempDir(), "storeB")
	exe := filepath.Join(t.TempDir(), "bin", "tool")
	placePad(t, exe, 128, machoCmd{lcRpath, storeA})
	if err := checkNoBuilderRpath(exe, storeB); err != nil {
		t.Errorf("another store's rpath was judged a builder path: %v", err)
	}
	if err := checkNoBuilderRpath(exe, storeA); err == nil {
		t.Error("its own store's rpath was not judged a builder path")
	}
}

func TestBuilderRpathRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		rpath, store string
		want         bool
	}{
		"no store":         {"/x/.pkgx", "", false},
		"relative entry":   {"@loader_path/..", "/x/.pkgx", false},
		"the store itself": {"/x/.pkgx", "/x/.pkgx", true},
		"inside the store": {"/x/.pkgx/a.org/b/v1/lib", "/x/.pkgx", true},
		"sibling dir":      {"/x/.pkgx-other", "/x/.pkgx", false},
		"elsewhere":        {"/usr/lib", "/x/.pkgx", false},
	} {
		if got := builderRpath(c.rpath, c.store); got != c.want {
			t.Errorf("%s: builderRpath(%q, %q) = %v, want %v", name, c.rpath, c.store, got, c.want)
		}
	}
}

// The guard FAILS THE BUILD. auditBuilt is what FixUp ends with; an artifact that
// still carries the fallback must not pass it.
func TestAuditBuiltRefusesAShippedBuilderRpath(t *testing.T) {
	store := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(store, "acme.org", "foo", "v1.0.0")
	placePad(t, filepath.Join(prefix, "bin", "foo"), 256, machoCmd{lcRpath, store})
	opts := Options{Prefix: prefix, Platform: "darwin", ZpkgDir: store}
	if err := auditBuilt(opts); !errors.Is(err, ErrBuilderRpath) {
		t.Fatalf("err = %v, want ErrBuilderRpath", err)
	}
	// A recipe that opted out of the rewrite did not ask for the removal.
	opts.Skips = []string{"fix-machos"}
	if err := auditBuilt(opts); err != nil {
		t.Fatalf("skipped recipe: %v", err)
	}
	// And FixUp, which rewrites first, ships it clean.
	opts.Skips = nil
	if err := FixUp(opts); err != nil {
		t.Fatal(err)
	}
	if err := checkNoBuilderRpath(filepath.Join(prefix, "bin", "foo"), store); err != nil {
		t.Fatal(err)
	}
}

// Removing the only rpath of a file that still names @rpath/... would ship it
// unloadable; that is refused here, loudly, not left to dyld.
func TestDroppingTheLastRpathOfAnRpathUserIsRefused(t *testing.T) {
	store := filepath.Join(t.TempDir(), ".pkgx")
	exe := filepath.Join(t.TempDir(), "lib", "libfoo.dylib") // outside the store
	placePad(t, exe, 256,
		machoCmd{lcRpath, store},
		machoCmd{lcLoadDylib, "@rpath/other.org/bar/v1/lib/libbar.dylib"},
	)
	err := rewriteMacho(exe, Options{Prefix: filepath.Dir(exe), Platform: "darwin", ZpkgDir: store})
	if !errors.Is(err, ErrDeadRpath) && !errors.Is(err, ErrBuilderOnlyRpath) {
		t.Fatalf("err = %v, want a dead-rpath refusal", err)
	}
}

// A universal binary is cleaned slice by slice.
func TestBuilderRpathIsRemovedFromEverySliceOfAFatBinary(t *testing.T) {
	store := filepath.Join(t.TempDir(), ".pkgx")
	cmds := []machoCmd{{lcRpath, store}, {lcRpath, "@loader_path/.."}}
	exe := buildFatMachO(t, cmds, cmds)
	n, err := dropMachoRpaths(exe, func(s string) bool { return builderRpath(s, store) })
	if err != nil || n != 2 {
		t.Fatalf("removed %d, err %v; want 2 (one per slice)", n, err)
	}
	for _, r := range rpathsOf(t, exe) {
		if r != "@loader_path/.." {
			t.Errorf("rpath %q survived", r)
		}
	}
}

func TestDropMachoRpathsOnANonMachoFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(p, []byte("not a mach-o"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := dropMachoRpaths(p, func(string) bool { return true }); err == nil {
		t.Fatal("a non-Mach-O was accepted")
	}
}

// A load-command run that lies about itself is refused, never edited.
func TestDropRpathCmdsRefusesAMalformedRun(t *testing.T) {
	le := binary.LittleEndian
	fresh := func() []byte {
		b, err := os.ReadFile(buildMachO(t, machoCmd{lcRpath, "/a"}, machoCmd{lcRpath, "/b"}))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	all := func(string) bool { return true }
	ncmd := 2
	for name, mut := range map[string]func(b []byte){
		"sizeofcmds past the slice": func(b []byte) { le.PutUint32(b[20:], uint32(len(b))) },
		"more commands than bytes":  func(b []byte) { ncmd = 9 },
		"cmdsize below the minimum": func(b []byte) { le.PutUint32(b[32+4:], 4) },
		"cmdsize past the run":      func(b []byte) { le.PutUint32(b[32+4:], uint32(len(b))) },
	} {
		ncmd = 2
		b := fresh()
		mut(b)
		if _, _, err := dropRpathCmds(b, le, 32, ncmd, all); !errors.Is(err, ErrMachoCmds) {
			t.Errorf("%s: err = %v, want ErrMachoCmds", name, err)
		}
	}
	// Nothing to remove leaves the bytes alone.
	b := fresh()
	orig := append([]byte(nil), b...)
	n, left, err := dropRpathCmds(b, le, 32, 2, func(string) bool { return false })
	if n != 0 || left != 2 || err != nil || string(b) != string(orig) {
		t.Errorf("no-op changed something: n=%d left=%d err=%v", n, left, err)
	}
	// An rpath whose string offset is nonsense is kept, not trusted.
	b = fresh()
	le.PutUint32(b[32+8:], 3)
	if n, _, err := dropRpathCmds(b, le, 32, 2, all); err != nil || n != 1 {
		t.Errorf("bad string offset: n=%d err=%v, want only the second rpath removed", n, err)
	}
}

// A failure of the removal itself stops the build; it is never swallowed into
// "nothing to remove".
func TestARemovalFailureStopsTheRewrite(t *testing.T) {
	boom := errors.New("boom")
	old := dropRpaths
	dropRpaths = func(string, func(string) bool) (int, error) { return 0, boom }
	t.Cleanup(func() { dropRpaths = old })
	exe := filepath.Join(t.TempDir(), "lib", "l.dylib")
	placePad(t, exe, 128, machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})
	if err := rewriteMacho(exe, Options{Platform: "darwin"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

// auditBuilt SAYS what it judged and what it skipped, by reason, and names the
// recipe, so a lane that stops being judged cannot read as clean.
func TestAuditBuiltCountsWhatItJudgedAndSkipped(t *testing.T) {
	store := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(store, "acme.org", "foo", "v1.0.0")
	placePad(t, filepath.Join(prefix, "bin", "a"), 256, machoCmd{lcRpath, "@loader_path/.."})
	placePad(t, filepath.Join(prefix, "lib", "b.dylib"), 256, machoCmd{lcRpath, "@loader_path/.."})
	if err := os.WriteFile(filepath.Join(prefix, "bin", "script"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(skips []string) string {
		var logged []string
		err := auditBuilt(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: store, Skips: skips,
			Log: func(s string) { logged = append(logged, s) }})
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(logged, "\n")
	}
	got := run(nil)
	for _, want := range []string{"acme.org/foo", "judged 2 Mach-O", "1 not Mach-O", "0 by the recipe's fix-machos"} {
		if !strings.Contains(got, want) {
			t.Errorf("judged case lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "is NOT judged") {
		t.Errorf("a judged recipe was reported as not judged:\n%s", got)
	}
	got = run([]string{"fix-machos"})
	for _, want := range []string{"acme.org/foo", "judged 0 Mach-O", "2 by the recipe's fix-machos", "acme.org/foo is NOT judged"} {
		if !strings.Contains(got, want) {
			t.Errorf("skipped case lacks %q:\n%s", want, got)
		}
	}
	// A prefix outside the store falls back to the directory above the version.
	if n := recipeName(Options{Prefix: "/elsewhere/proj/v1", ZpkgDir: store}); n != "proj" {
		t.Errorf("recipeName outside the store = %q", n)
	}
}
