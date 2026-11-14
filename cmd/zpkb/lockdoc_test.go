package main

import (
	"bytes"
	"errors"

	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// A lock has to survive the round trip, or `--check` is checking a file it
// wrote differently from the one it reads.
func TestALockRoundTrips(t *testing.T) {
	d := lockDoc{
		Version: lockfileVersion, Platform: "linux/s390x", Generated: "2026-10-05T09:00:00Z",
		ZPKB: "v0.6.1", Roots: []string{"go-zpkg/base-toolchain", "zlib.net"},
		Pantry: "aaa", Overlay: "bbb",
		Pins: []lockedPin{{Project: "a.org", Version: "1", Spec: "sha256:11"}, {Project: "b.org", Version: "2", Spec: "sha256:22"}},
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "l.hcl")
	if err := os.WriteFile(p, []byte(renderLock(d)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != d.Version || got.Platform != d.Platform || got.Generated != d.Generated ||
		got.ZPKB != d.ZPKB || got.Pantry != d.Pantry || got.Overlay != d.Overlay {
		t.Errorf("header did not survive:\n got %+v\nwant %+v", got, d)
	}
	if strings.Join(got.Roots, " ") != strings.Join(d.Roots, " ") {
		t.Errorf("roots = %v", got.Roots)
	}
	if len(got.Pins) != 2 || got.Pins[0] != d.Pins[0] || got.Pins[1] != d.Pins[1] {
		t.Errorf("pins = %+v", got.Pins)
	}
}

// Every way a lock can fail to be one. Each is a separate refusal because
// each tells the reader something different about the file in their hand.
func TestReadLockRefusals(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct{ name, path, want string }{
		{"missing file", filepath.Join(dir, "nope.hcl"), "no such file"},
		{"not HCL", write("bad.hcl", "locked = {\n"), "hcl: parse"},
		{"no locked block", write("empty.hcl", "platform = \"linux/x86-64\"\n"), "not a lock"},
		{"an entry that is not an object", write("flat.hcl", "locked = { \"a.org\" = \"1.2.3\" }\n"),
			"is not a { version"},
		{"a newer format", write("future.hcl",
			"lockfile_version = 99\nlocked = { \"a.org\" = { version = \"1\", spec = \"s\" } }\n"),
			"read it with a newer one"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := readLock(c.path)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v\n  does not say %q", err, c.want)
			}
		})
	}
}

// A field of the wrong type reads as its zero rather than killing the file:
// the comparison then names it, which is more use than refusing 40 good
// lines over one bad one.
//
// Asserted through readLock rather than through the coercion helpers it
// used to have. Those moved to artifact with the rest of the format, and
// testing the BEHAVIOUR here is what tells us the move kept it — a test of
// a helper this package no longer owns would have had to be deleted, and
// deleting it would have left the property unchecked on this side.
func TestLockFieldCoercion(t *testing.T) {
	prev := osReadFile
	osReadFile = func(string) ([]byte, error) {
		return []byte("lockfile_version = 1\nplatform = 42\nroots = \"not-a-list\"\n" +
			"locked = {\n  \"curl.se\" = { version = \"8.17.0\", spec = \"sha256:a\" }\n}\n"), nil
	}
	t.Cleanup(func() { osReadFile = prev })

	d, err := readLock("odd.lock.hcl")
	if err != nil {
		t.Fatalf("one odd field killed the file: %v", err)
	}
	if d.Platform != "" || len(d.Roots) != 0 {
		t.Errorf("a wrong type was not read as its zero: %+v", d)
	}
	if len(d.Pins) != 1 || d.Pins[0].Version != "8.17.0" {
		t.Errorf("the good lines were lost with the bad one: %+v", d.Pins)
	}
}

// The four things a check can find, and the one it must NOT invent.
func TestCompareLock(t *testing.T) {
	was := []lockedPin{
		{Project: "same.org", Version: "1", Spec: "sha256:aa"},
		{Project: "moved.org", Version: "1", Spec: "sha256:bb"},
		{Project: "edited.org", Version: "1", Spec: "sha256:cc"},
		{Project: "gone.org", Version: "1", Spec: "sha256:dd"},
	}
	now := []lockedPin{
		{Project: "same.org", Version: "1", Spec: "sha256:aa"},
		{Project: "moved.org", Version: "2", Spec: "sha256:bb"},
		{Project: "edited.org", Version: "1", Spec: "sha256:ZZ"},
		{Project: "joined.org", Version: "9", Spec: "sha256:ee"},
	}
	got := map[string]string{}
	for _, d := range compareLock(was, now) {
		got[d.project] = d.was + " → " + d.now
	}
	if _, ok := got["same.org"]; ok {
		t.Errorf("a project that did not move was reported: %q", got["same.org"])
	}
	if got["moved.org"] != "1 → 2" {
		t.Errorf("moved.org = %q", got["moved.org"])
	}
	// The case the spec hash exists for: same version, different inputs.
	if !strings.Contains(got["edited.org"], "same version, so something it is built FROM changed") {
		t.Errorf("edited.org = %q", got["edited.org"])
	}
	if !strings.Contains(got["gone.org"], "gone from the closure") {
		t.Errorf("gone.org = %q", got["gone.org"])
	}
	if !strings.Contains(got["joined.org"], "not in the lock") {
		t.Errorf("joined.org = %q", got["joined.org"])
	}
	if n := len(compareLock(was, was)); n != 0 {
		t.Errorf("a lock compared with itself reported %d drifts", n)
	}
}

func TestLockAge(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-10-05T11:30:00Z": "30 minute(s) old",
		"2026-10-05T06:00:00Z": "6 hour(s) old",
		"2026-10-01T12:00:00Z": "4 day(s) old",
		"not a time":           "unknown age",
	} {
		if got := lockAge(in, now); got != want {
			t.Errorf("lockAge(%q) = %q, want %q", in, got, want)
		}
	}
}

// bk records which bk wrote the lock, as Spack records which spack wrote
// its lockfile. A binary with no version stamped in says so rather than
// leaving the field out.
func TestBKVersion(t *testing.T) {
	prev := buildInfo
	t.Cleanup(func() { buildInfo = prev })

	buildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true
	}
	if got := bkVersion(); got != "v1.2.3" {
		t.Errorf("bkVersion = %q", got)
	}
	buildInfo = func() (*debug.BuildInfo, bool) { return nil, false }
	if got := bkVersion(); got != "(unknown)" {
		t.Errorf("with no build info, bkVersion = %q", got)
	}
	buildInfo = func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{}, true }
	if got := bkVersion(); got != "(unknown)" {
		t.Errorf("with an empty version, bkVersion = %q", got)
	}
}

// --check end to end through runLock: write a lock, check it unchanged, then
// change a build script and check it again. The second half is the point —
// the version does not move and the lock must still notice.
func TestCheckSeesARecipeEditedUnderAPin(t *testing.T) {
	p, files := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	lockPath := filepath.Join(t.TempDir(), "l.hcl")

	// lockbed stubs osWriteFile into a map, so write through the same seam.
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-o", lockPath, "lib.org"}, &out, &errb); code != 0 {
		t.Fatalf("writing: code=%d err=%q", code, errb.String())
	}
	body := (*files)[lockPath]
	if len(body) == 0 {
		t.Fatalf("nothing was written to %s", lockPath)
	}
	if err := os.WriteFile(lockPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := runLock([]string{"--pantry", p, "--check", lockPath}, &out, &errb); code != 0 {
		t.Fatalf("an unchanged pantry reported drift: code=%d\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "none moved") {
		t.Errorf("unchanged check said: %q", out.String())
	}

	// Edit the BUILD, not the versions. A version-only lock cannot see this.
	edited := strings.Replace(lockableRecipe, "script: [make]", "script: [make, -j1]", 1)
	if err := os.WriteFile(filepath.Join(p, "projects", "lib.org", "package.yml"), []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := runLock([]string{"--pantry", p, "--check", lockPath}, &out, &errb); code != 1 {
		t.Fatalf("a recipe edited under a pin was not reported: code=%d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "same version, so something it is built FROM changed") {
		t.Errorf("the check does not say WHAT moved:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "1 of 1 moved") {
		t.Errorf("no count:\n%s", out.String())
	}
}

// --check takes its roots from the file. Naming one on the command line
// would let the two disagree, and the answer would be about a different
// question from the one the file asks.
func TestCheckRefusesRootsOnTheCommandLine(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLock([]string{"--check", "l.hcl", "zlib.net"}, &out, &errb); code != 2 {
		t.Fatalf("code=%d; want 2", code)
	}
	if !strings.Contains(errb.String(), "a different question") {
		t.Errorf("stderr=%q", errb.String())
	}
}

func TestCheckRefusesALockItCannotUse(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	entry := "locked = { \"a.org\" = { version = \"1\", spec = \"s\" } }\n"
	for _, c := range []struct{ name, body, want string }{
		{"no platform", "roots = [\"a.org\"]\n" + entry, "names no platform"},
		{"no roots", "platform = \"linux/x86-64\"\n" + entry, "names no roots"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := runLock([]string{"--check", write(c.name+".hcl", c.body)}, &out, &errb); code != 2 {
				t.Fatalf("code=%d; want 2", code)
			}
			if !strings.Contains(errb.String(), c.want) {
				t.Errorf("stderr=%q", errb.String())
			}
		})
	}
	// And one it cannot read at all.
	var out, errb bytes.Buffer
	if code := runLock([]string{"--check", filepath.Join(dir, "absent.hcl")}, &out, &errb); code != 2 {
		t.Fatalf("a missing lock: code=%d; want 2", code)
	}
}

// A revision that moved is SAID and is not fatal on its own: a pantry can
// move without moving any answer, and calling that drift would make the
// check cry wolf until nobody ran it.
func TestCheckSaysARevisionMovedWithoutCallingItDrift(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	lock := filepath.Join(t.TempDir(), "l.hcl")
	// A lock claiming a revision this pantry does not have.
	body := renderLock(lockDoc{
		Version: lockfileVersion, Platform: "linux/x86-64", Generated: "2026-10-05T09:00:00Z",
		Roots: []string{"lib.org"}, Pantry: "a-revision-from-somewhere-else",
		Pins: []lockedPin{{Project: "lib.org", Version: "1.2.4", Spec: lockedSpecOf(t, p, "lib.org")}},
	})
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runLock([]string{"--pantry", p, "--check", lock}, &out, &errb)
	if !strings.Contains(out.String(), "pantry revision differs: a-revision-from-somewhere-else →") {
		t.Errorf("the moved revision is not reported:\n%s", out.String())
	}
	if code != 0 {
		t.Errorf("a moved revision alone was treated as drift: code=%d\n%s", code, out.String())
	}
}

// lockedSpecOf is the spec hash this pantry currently produces for one
// project — so a fixture lock can agree with it about everything except the
// field under test.
func lockedSpecOf(t *testing.T, pantryDir, proj string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", pantryDir, "--platform", "linux/x86-64", proj}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	_, s, _ := strings.Cut(out.String(), `spec = "`)
	s, _, _ = strings.Cut(s, `"`)
	return s
}

// A check whose closure comes back empty says nothing about the lock, and
// must not say "none moved".
func TestCheckRefusesAnEmptyClosure(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "l.hcl")
	body := renderLock(lockDoc{
		Version: lockfileVersion, Platform: "linux/x86-64", Generated: "2026-10-05T09:00:00Z",
		Roots: []string{"ghost.org"}, Pins: []lockedPin{{Project: "ghost.org", Version: "1", Spec: "sha256:aa"}},
	})
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", t.TempDir(), "--check", lock}, &out, &errb); code != 2 {
		t.Fatalf("code=%d; want 2\n%s%s", code, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "none moved") {
		t.Error("an empty closure reported that nothing moved")
	}
	// And the walk's warning reached the caller rather than being swallowed.
	if !strings.Contains(errb.String(), "ghost.org") {
		t.Errorf("the closure's own warning was lost: %q", errb.String())
	}
}

// An unparseable --overrides is a startup error for --check too.
func TestCheckRefusesUnparseableOverrides(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	ov := t.TempDir()
	if err := os.WriteFile(filepath.Join(ov, "broken.hcl"), []byte("project \"x\" {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(t.TempDir(), "l.hcl")
	body := renderLock(lockDoc{
		Version: lockfileVersion, Platform: "linux/x86-64", Generated: "2026-10-05T09:00:00Z",
		Roots: []string{"lib.org"}, Pins: []lockedPin{{Project: "lib.org", Version: "1.2.4", Spec: "sha256:aa"}},
	})
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--overrides", ov, "--check", lock}, &out, &errb); code != 2 {
		t.Fatalf("code=%d; want 2 (stderr=%q)", code, errb.String())
	}
}

// An unresolved project is an answer nobody got, not a pin that moved. It
// must be named, and it must make the check fail — but it must not be
// counted among the things that moved, or a registry outage would read as a
// pantry that changed.
func TestCheckKeepsUnresolvedApartFromDrift(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	lock := filepath.Join(t.TempDir(), "l.hcl")
	body := renderLock(lockDoc{
		Version: lockfileVersion, Platform: "linux/x86-64", Generated: "2026-10-05T09:00:00Z",
		Roots: []string{"lib.org"}, Pantry: gitRevOf(p),
		Pins: []lockedPin{{Project: "lib.org", Version: "1.2.4", Spec: lockedSpecOf(t, p, "lib.org")}},
	})
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := recipeLoader
	recipeLoader = func(set *logical.Set, overlay, pantry, proj string) (*pantry.Recipe, string, error) {
		return nil, "", errors.New("the registry is down")
	}
	t.Cleanup(func() { recipeLoader = prev })

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--check", lock}, &out, &errb); code != 1 {
		t.Fatalf("code=%d; want 1\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "unresolved: lib.org") {
		t.Errorf("the unresolved project is not named: %q", errb.String())
	}
	if strings.Contains(out.String(), "moved") && !strings.Contains(out.String(), "gone from the closure") {
		t.Errorf("an unresolved project was counted as drift:\n%s", out.String())
	}
}

// ⛔ --check MUST APPLY THE ROOTS' CONSTRAINTS, which it reads from the file.
//
// A lock written for `app.org@1.2.3` pins 1.2.3 while the recipe also offers
// 1.2.4. Re-resolving without the `@1.2.3` picks 1.2.4 and reports drift
// against a lock that is exactly right — a report of movement that never
// happened, which is the one thing --check must not produce.
func TestLockCheckAppliesTheRootsConstraintFromTheFile(t *testing.T) {
	p, files := lockbed(t, map[string]string{"app.org": lockableRecipe})
	lockPath := filepath.Join(t.TempDir(), "pinned.hcl")

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "-o", lockPath, "app.org@1.2.3"}, &out, &errb); code != 0 {
		t.Fatalf("writing: code=%d err=%q", code, errb.String())
	}
	body := (*files)[lockPath]
	if !strings.Contains(string(body), `version = "1.2.3"`) {
		t.Fatalf("the fixture did not pin the older version, so this proves nothing:\n%s", body)
	}
	if err := os.WriteFile(lockPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	if code := runLock([]string{"--pantry", p, "--check", lockPath}, &out, &errb); code != 0 {
		t.Fatalf("a constrained lock was reported as drifted: code=%d\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "none moved") {
		t.Errorf("check said: %q", out.String())
	}
}
