package main

import (
	"bytes"

	"errors"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lockbed gives a pantry, a frozen clock and a captured write, so a lock's
// output is a fact a test can assert rather than a thing that changes every
// second.
func lockbed(t *testing.T, recipes map[string]string) (dir string, written *map[string][]byte) {
	t.Helper()
	dir = t.TempDir()
	for proj, body := range recipes {
		p := filepath.Join(dir, "projects", proj)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prevNow, prevWrite := lockNow, osWriteFile
	lockNow = func() time.Time { return time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC) }
	files := map[string][]byte{}
	osWriteFile = func(name string, b []byte, _ os.FileMode) error { files[name] = b; return nil }

	// ⛔ THE FIXTURE PANTRY HAS NO REGISTRY BEHIND IT. `bk lock` now asks
	// whether each pin is published, and left on the real function every
	// test in this file would reach ghcr for a project like "app.org" that
	// has never existed — putting the network inside a unit test and making
	// the suite fail offline. Caught by asking what the new call did to the
	// tests that were already here, rather than by noticing them go red.
	//
	// It answers "published", so these tests measure what they always
	// measured. Publication is exercised on its own in lockpublished_test.go,
	// where both answers are given deliberately.
	prevTag, prevPick := lockPublishedTagFor, lockPickPublished
	lockPublishedTagFor = func(_ string, v bottle.Ver, osn, arch string) (string, bool, error) {
		return v.Raw + "--" + osn + "-" + arch, true, nil
	}
	lockPickPublished = func(_, _, _, _ string) (bottle.Ver, error) {
		return bottle.Ver{}, errors.New("the fixture has no registry")
	}

	t.Cleanup(func() {
		lockNow, osWriteFile = prevNow, prevWrite
		lockPublishedTagFor, lockPickPublished = prevTag, prevPick
	})
	return dir, &files
}

const lockableRecipe = "versions:\n  - 1.2.3\n  - 1.2.4\ndistributable:\n  url: https://x/v{{version}}.tgz\nbuild:\n  script: [make]\n"

func TestLockPinsTheResolvedVersions(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"app.org": "dependencies:\n  lib.org: '*'\n" + lockableRecipe,
		"lib.org": lockableRecipe,
	})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{`"app.org" = { version = "1.2.4"`, `"lib.org" = { version = "1.2.4"`, "linux/x86-64", "2026-10-05T09:00:00Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("the lock does not carry %q:\n%s", want, got)
		}
	}
	// Sorted by project, not in build order: a lock is read as a diff, and a
	// topological order makes every line move when one dependency does.
	if strings.Index(got, `"app.org"`) > strings.Index(got, `"lib.org"`) {
		t.Error("the lock is in build order, not sorted")
	}
	// It says where it stops. A lock that quietly guarantees less than a
	// reader assumes is worse than one that names its limit.
	if !strings.Contains(got, "does NOT pin: the BYTES of the built bottle") {
		t.Errorf("the lock does not say what it leaves unpinned:\n%s", got)
	}
}

// A pantry that is a plain directory is a legitimate thing to lock against —
// an unpacked tarball, a fixture. But the lock must not claim a revision it
// does not have.
func TestLockSaysWhenThereIsNoRevisionToRecord(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	var out, errb bytes.Buffer
	runLock([]string{"--pantry", p, "lib.org"}, &out, &errb)
	if !strings.Contains(out.String(), "not a git checkout") {
		t.Errorf("a non-git pantry was not reported:\n%s", out.String())
	}
}

// A project whose version cannot be resolved is a HOLE, and a lock with a
// hole must not read as success — the next person would commit it.
func TestAnUnresolvedProjectFailsTheLock(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"lib.org": "distributable:\n  url: https://x/v{{version}}.tgz\nbuild:\n  script: [make]\n",
	})
	var out, errb bytes.Buffer
	code := runLock([]string{"--pantry", p, "lib.org"}, &out, &errb)
	if code == 0 {
		t.Error("a lock with an unresolved project reported success")
	}
	if !strings.Contains(errb.String(), "unresolved: lib.org") {
		t.Errorf("the hole was not named: %q", errb.String())
	}
}

func TestLockRefusesAnEmptyRequest(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLock(nil, &out, &errb); code != 2 {
		t.Fatalf("code=%d; want 2", code)
	}
	if !strings.Contains(errb.String(), "not an empty lock, it is a mistake") {
		t.Errorf("stderr=%q", errb.String())
	}
}

// Go's flag package stops at the first non-flag argument, so a flag after a
// project name is silently a project name. Measured on myself within a
// minute of writing the command.
func TestLockRefusesAFlagAfterAProjectName(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "lib.org", "-o", "/tmp/x"}, &out, &errb); code != 2 {
		t.Fatalf("code=%d; want 2", code)
	}
	if !strings.Contains(errb.String(), "comes after a project name") {
		t.Errorf("stderr=%q", errb.String())
	}
}

func TestLockWritesToAFileWhenAsked(t *testing.T) {
	p, files := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "-o", "/tmp/out.hcl", "lib.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	b, ok := (*files)["/tmp/out.hcl"]
	if !ok {
		t.Fatalf("nothing was written; files=%v", *files)
	}
	if !strings.Contains(string(b), `"lib.org" = { version = "1.2.4"`) {
		t.Errorf("file=%q", b)
	}
	if out.Len() != 0 {
		t.Errorf("it wrote to the file AND to stdout: %q", out.String())
	}
	if !strings.Contains(errb.String(), "1 project(s) pinned") {
		t.Errorf("it did not say what it wrote: %q", errb.String())
	}
}

func TestLockReportsAWriteFailure(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	osWriteFile = func(string, []byte, os.FileMode) error { return errors.New("read-only file system") }
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "-o", "/x", "lib.org"}, &out, &errb); code != 1 {
		t.Fatalf("code=%d; want 1", code)
	}
	if !strings.Contains(errb.String(), "read-only file system") {
		t.Errorf("stderr=%q", errb.String())
	}
}

// A closure that read nothing is a failure, not a clean empty lock.
func TestLockRefusesAnEmptyClosure(t *testing.T) {
	p, _ := lockbed(t, map[string]string{})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "nope.org"}, &out, &errb); code != 1 {
		t.Fatalf("code=%d; want 1", code)
	}
	if !strings.Contains(errb.String(), "is a failure and not a clean result") {
		t.Errorf("stderr=%q", errb.String())
	}
}

func TestLockRejectsBadFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runLock([]string{"-nope"}, &out, &errb); code != 2 {
		t.Errorf("code=%d; want 2", code)
	}
}

// An overlay is recorded too, and a real git checkout gives a real hash.
// Both halves matter: the overlay line only appears when one is given, and
// the hash is what makes the lock replayable.
func TestLockRecordsBothRevisions(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	ov := t.TempDir()

	// A real repository, because `(not a git checkout)` is the other branch
	// and asserting the hash means producing one.
	repo, err := gogit.PlainInit(ov, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ov, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("x"); err != nil {
		t.Fatal(err)
	}
	h, err := wt.Commit("c", &gogit.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@e", When: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--overlay", ov, "lib.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), `overlay          = "`+h.String()+`"`) {
		t.Errorf("the overlay revision is not recorded:\n%s", out.String())
	}
}

// An empty directory name is not a checkout and must not be reported as a
// broken one: `--overlay ""` means "no overlay", not "an overlay I failed to
// read".
func TestGitRevOfDistinguishesAbsentFromUnreadable(t *testing.T) {
	if got := gitRevOf(""); got != "(none)" {
		t.Errorf("gitRevOf(\"\") = %q; want (none)", got)
	}
	if got := gitRevOf(t.TempDir()); !strings.Contains(got, "not a git checkout") {
		t.Errorf("a plain directory = %q", got)
	}
	// A repository with no commit yet has no HEAD to record.
	empty := t.TempDir()
	if _, err := gogit.PlainInit(empty, false); err != nil {
		t.Fatal(err)
	}
	if got := gitRevOf(empty); got != "(no HEAD)" {
		t.Errorf("an unborn HEAD = %q; want (no HEAD)", got)
	}
}

// A project in the closure whose recipe cannot be read is a hole like any
// other, and must be named rather than dropped.
func TestLockNamesAProjectWhoseRecipeVanishes(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"app.org": "dependencies:\n  lib.org: '*'\n" + lockableRecipe,
		"lib.org": lockableRecipe,
	})
	// Remove lib.org AFTER the closure can see it: the walk reads it, the
	// per-project resolve cannot.
	prev := recipeLoader
	recipeLoader = func(set *logical.Set, overlay, pantry, proj string) (*pantry.Recipe, string, error) {
		if proj == "lib.org" {
			return nil, "", errors.New("vanished")
		}
		return prev(set, overlay, pantry, proj)
	}
	t.Cleanup(func() { recipeLoader = prev })

	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "app.org"}, &out, &errb); code != 1 {
		t.Fatalf("code=%d; want 1", code)
	}
	if !strings.Contains(errb.String(), "unresolved: lib.org (no recipe:") {
		t.Errorf("stderr=%q", errb.String())
	}
}

// An --overrides directory that does not parse is a startup error, not a lock
// with a silent hole in its overrides: a run that ignored the overrides would
// pin the versions the UNOVERRIDDEN recipes resolve to, which is a different
// answer wearing the same shape.
func TestLockRefusesUnparseableOverrides(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	ov := t.TempDir()
	if err := os.WriteFile(filepath.Join(ov, "broken.hcl"), []byte("project \"x\" {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--overrides", ov, "lib.org"}, &out, &errb); code != 2 {
		t.Fatalf("code=%d; want 2 (stderr=%q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "lock:") {
		t.Errorf("the refusal does not name the command: %q", errb.String())
	}
}

// TestLockDispatch covers the main-loop `case "lock"` route.
func TestLockDispatch(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"lib.org": lockableRecipe})
	code, out, errs := run2(t, "lock", "--pantry", p, "lib.org")
	if code != 0 {
		t.Fatalf("dispatch lock code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, `locked = {`) {
		t.Errorf("dispatch lock out=%q", out)
	}
}

// specHash is a MERKLE hash, and this is the control that says so: a change
// to a leaf must move the leaf AND everything above it, and a change at the
// top must move the top ALONE.
//
// Without both halves the test is worthless in the usual two ways. A hash
// that ignored dependencies would pass the second half. A hash that mixed
// every project together — the whole-closure digest it is easy to write by
// accident — would pass the first.
func TestSpecHashMovesExactlyTheSubtreeAbove(t *testing.T) {
	// top → mid → leaf, plus `other` depending on nothing: a project with no
	// relation to the edit must not move, or "everything moved" would read as
	// a pass.
	base := map[string]string{
		"top.org":   "dependencies:\n  mid.org: '*'\n" + lockableRecipe,
		"mid.org":   "dependencies:\n  leaf.org: '*'\n" + lockableRecipe,
		"leaf.org":  lockableRecipe,
		"other.org": lockableRecipe,
	}
	lockOf := func(t *testing.T, recipes map[string]string) map[string]string {
		t.Helper()
		p, _ := lockbed(t, recipes)
		var out, errb bytes.Buffer
		if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "top.org", "other.org"}, &out, &errb); code != 0 {
			t.Fatalf("code=%d err=%q", code, errb.String())
		}
		got := map[string]string{}
		for _, line := range strings.Split(out.String(), "\n") {
			proj, rest, ok := strings.Cut(strings.TrimSpace(line), " = { version = ")
			if !ok {
				continue
			}
			_, spec, _ := strings.Cut(rest, `spec = "`)
			spec, _, _ = strings.Cut(spec, `"`)
			got[strings.Trim(proj, `"`)] = spec
		}
		if len(got) != 4 {
			t.Fatalf("expected 4 pins, got %v (out=%s)", got, out.String())
		}
		return got
	}

	before := lockOf(t, base)

	// 1. Edit the LEAF's build script. Everything above it must move.
	edited := map[string]string{}
	for k, v := range base {
		edited[k] = v
	}
	edited["leaf.org"] = strings.Replace(lockableRecipe, "script: [make]", "script: [make, -j1]", 1)
	after := lockOf(t, edited)
	for _, proj := range []string{"leaf.org", "mid.org", "top.org"} {
		if before[proj] == after[proj] {
			t.Errorf("%s did not move when the leaf's build script changed — the hash is not a Merkle over the dependencies", proj)
		}
	}
	if before["other.org"] != after["other.org"] {
		t.Errorf("other.org moved although nothing it depends on changed: %s → %s", before["other.org"], after["other.org"])
	}

	// 2. Edit the TOP. Nothing below it may move.
	edited2 := map[string]string{}
	for k, v := range base {
		edited2[k] = v
	}
	edited2["top.org"] = "dependencies:\n  mid.org: '*'\n" + strings.Replace(lockableRecipe, "script: [make]", "script: [make, check]", 1)
	after2 := lockOf(t, edited2)
	if before["top.org"] == after2["top.org"] {
		t.Error("top.org did not move when its own build script changed")
	}
	for _, proj := range []string{"mid.org", "leaf.org", "other.org"} {
		if before[proj] != after2[proj] {
			t.Errorf("%s moved when a project ABOVE it changed: %s → %s", proj, before[proj], after2[proj])
		}
	}
}

// Reformatting a recipe must not move its hash — the hash is over the PARSED
// recipe, which is what makes it survive a reflow of the pantry. And the same
// recipe on a different platform must hash differently, because it is a
// different build.
func TestSpecHashIgnoresFormattingAndSeesThePlatform(t *testing.T) {
	spec := func(t *testing.T, body, platform string) string {
		t.Helper()
		p, _ := lockbed(t, map[string]string{"lib.org": body})
		var out, errb bytes.Buffer
		if code := runLock([]string{"--pantry", p, "--platform", platform, "lib.org"}, &out, &errb); code != 0 {
			t.Fatalf("code=%d err=%q", code, errb.String())
		}
		_, s, _ := strings.Cut(out.String(), `spec = "`)
		s, _, _ = strings.Cut(s, `"`)
		return s
	}
	tidy := "versions:\n  - 1.2.3\n  - 1.2.4\ndistributable:\n  url: https://x/v{{version}}.tgz\nbuild:\n  script: [make]\n"
	// Same meaning: comments, a flow sequence rewritten as a block one, and a
	// different key order.
	reflowed := "# the same recipe, spelled differently\nbuild:\n  script:\n    - make\ndistributable:\n  url: https://x/v{{version}}.tgz\nversions:\n  - 1.2.3\n  - 1.2.4\n"
	if a, b := spec(t, tidy, "linux/x86-64"), spec(t, reflowed, "linux/x86-64"); a != b {
		t.Errorf("reformatting moved the hash:\n  %s\n  %s", a, b)
	}
	if a, b := spec(t, tidy, "linux/x86-64"), spec(t, tidy, "darwin/aarch64"); a == b {
		t.Error("the same recipe hashes alike on two platforms — the platform is not in the hash")
	}
}

// A recipe that cannot be serialised has no hash, and the project must be
// NAMED as unresolved rather than written into the lock without one.
func TestSpecHashRefusesAnUnserialisableRecipe(t *testing.T) {
	bad := &pantry.Recipe{Build: map[string]any{"script": make(chan int)}}
	if _, err := specHash([]*pantry.Recipe{bad}, "x.org", "1", target.Target{Platform: "linux", Arch: "x86-64"}, nil, nil); err == nil {
		t.Fatal("a recipe json cannot marshal produced a hash")
	}
}

// A dependency the closure could not read is recorded as unknown, not
// omitted: omitting it would make "no recipe for X" and "X is not a
// dependency" hash alike.
func TestSpecHashDistinguishesAnUnreadableDepFromNoDep(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := []*pantry.Recipe{{Build: "make"}}
	none, err := specHash(r, "x.org", "1", tgt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := specHash(r, "x.org", "1", tgt, nil, []string{"y.org"})
	if err != nil {
		t.Fatal(err)
	}
	known, err := specHash(r, "x.org", "1", tgt, map[string]string{"y.org": "sha256:aa"}, []string{"y.org"})
	if err != nil {
		t.Fatal(err)
	}
	if none == unknown || unknown == known || none == known {
		t.Errorf("three different dependency situations do not hash differently:\n  none    %s\n  unknown %s\n  known   %s", none, unknown, known)
	}
}

// shortHash is what gets printed when a line has to fit; it must not invent
// digits for a hash shorter than the prefix it takes.
func TestShortHash(t *testing.T) {
	if got := shortHash("sha256:0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("shortHash = %q", got)
	}
	if got := shortHash("abc"); got != "abc" {
		t.Errorf("a short hash was padded or cut: %q", got)
	}
}

// specDeps reduces BOTH halves of a recipe, de-duplicated and sorted: the
// hash must describe the graph the closure walked, and the closure reads the
// overlay's half and the pantry's half as two recipes.
func TestSpecDepsUnionsBothHalves(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	got := specDeps([]*pantry.Recipe{
		{Dependencies: map[string]any{"b.org": "*", "a.org": "*"}},
		{Dependencies: map[string]any{"a.org": "*", "c.org": "*"}},
	}, tgt)
	if strings.Join(got, " ") != "a.org b.org c.org" {
		t.Errorf("specDeps = %v", got)
	}
}

// A recipe YAML accepts and JSON cannot represent — a mapping with a
// non-string key, which YAML allows and JSON does not — leaves a project with
// no spec hash. It must be NAMED as unresolved, and the run must not succeed.
//
// This is not hypothetical arithmetic: `true: x` and `1.5: x` are both legal
// YAML mappings, and yaml.v3 hands them over as map[any]any.
func TestLockNamesAProjectWhoseRecipeCannotBeHashed(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"odd.org": "versions:\n  - 1.2.3\nbuild:\n  script: [make]\nprovides:\n  true: x\n",
	})
	var out, errb bytes.Buffer
	code := runLock([]string{"--pantry", p, "odd.org"}, &out, &errb)
	if code != 1 {
		t.Fatalf("code=%d; want 1 (stderr=%q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "unresolved: odd.org") {
		t.Errorf("the project is not named: %q", errb.String())
	}
	// Checked inside the `locked` block, not in the whole output: the roots
	// line names it too, and a test that looked at the whole file would pass
	// whatever the lock contained.
	_, block, _ := strings.Cut(out.String(), "locked = {")
	if strings.Contains(block, "odd.org") {
		t.Errorf("a project with no hash was written into the lock:\n%s", block)
	}
}

// ⛔ A ROOT'S OWN CONSTRAINT IS APPLIED, and this is the arm a `-runnable`
// test cannot reach: that one resolves through publishedVersionFor and the
// demands list, this one through versions.Resolve. A mutation that replaced
// the root's constraint with "" SURVIVED the suite until this existed.
//
// The reported case was `bk lock nodejs.org@22` writing a file whose `roots`
// said 22 and whose pin said 26 (go-zpkg/bk#140).
func TestLockAppliesARootsOwnConstraint(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"app.org": lockableRecipe})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org@1.2.3"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, `"app.org" = { version = "1.2.3"`) {
		t.Errorf("the root's constraint was not applied:\n%s", got)
	}
	// ⛔ AND THE FILE AGREES WITH ITSELF. roots and the pin are the two halves
	// a reader compares, and the defect was that they contradicted.
	if !strings.Contains(got, `roots            = ["app.org@1.2.3"]`) {
		t.Errorf("roots does not record what was asked:\n%s", got)
	}
}

// The control: with no constraint the newest still wins. Without this,
// "always pick the oldest" would pass the test above.
func TestLockWithoutAConstraintStillTakesTheNewest(t *testing.T) {
	p, _ := lockbed(t, map[string]string{"app.org": lockableRecipe})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), `"app.org" = { version = "1.2.4"`) {
		t.Errorf("an unconstrained root did not take the newest:\n%s", out.String())
	}
}

// ⛔ AND IT IS NOT PROPAGATED. The constraint belongs to the root; a
// dependency reached through the walk is still resolved by its own recipe,
// which is go-zpkg/bk#140 and is NOT fixed here. Pinning that distinction so
// a later change cannot widen it by accident without a test moving.
func TestLockDoesNotPropagateARootsConstraintToItsDependencies(t *testing.T) {
	p, _ := lockbed(t, map[string]string{
		"app.org": "dependencies:\n  lib.org: '*'\n" + lockableRecipe,
		"lib.org": lockableRecipe,
	})
	var out, errb bytes.Buffer
	if code := runLock([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org@1.2.3"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, `"app.org" = { version = "1.2.3"`) {
		t.Errorf("the root itself was not pinned:\n%s", got)
	}
	if !strings.Contains(got, `"lib.org" = { version = "1.2.4"`) {
		t.Errorf("the dependency took the root's constraint; that is not what this fixes:\n%s", got)
	}
	if !strings.Contains(errb.String(), "NOT propagated through the walk") {
		t.Errorf("the limit is not said out loud: %q", errb.String())
	}
}
