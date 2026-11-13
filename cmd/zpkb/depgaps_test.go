package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

const regJSON = `[
 {"name":"openssl.org","os":"linux","arch":"x86-64","version":"3.5.0"},
 {"name":"openssl.org","os":"darwin","arch":"aarch64","version":"1.1.1w"},
 {"name":"zlib.net","os":"linux","arch":"x86-64","version":"1.3.2"}
]`

func TestPublishedVersions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.json")
	if err := os.WriteFile(p, []byte(regJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	have, err := publishedVersions(p, "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	// The darwin row must not leak into the linux answer: a version published
	// only for another platform cannot satisfy this one.
	if got := have["openssl.org"]; len(got) != 1 || got[0] != "3.5.0" {
		t.Fatalf("openssl.org = %v", got)
	}
	if _, ok := have["nothing.org"]; ok {
		t.Error("an unpublished project must be absent, not empty")
	}
}

func TestPublishedVersionsErrors(t *testing.T) {
	if _, err := publishedVersions(filepath.Join(t.TempDir(), "missing.json"), "linux", "x86-64"); err == nil {
		t.Error("a missing registry must fail loudly, not silently rank nothing")
	}
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte("{oops"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := publishedVersions(p, "linux", "x86-64"); err == nil {
		t.Error("unparseable registry must fail")
	}
}

func TestAnySatisfies(t *testing.T) {
	// The distinction the whole report rests on: >=1.1 is unbounded above, so
	// openssl 3.x meets it and the recipe already resolves.
	if !anySatisfies([]string{"3.5.0"}, ">=1.1") {
		t.Error(">=1.1 must be satisfied by 3.5.0")
	}
	if anySatisfies([]string{"3.5.0"}, "^1.1") {
		t.Error("^1.1 must NOT be satisfied by 3.5.0")
	}
	if anySatisfies(nil, "^1") {
		t.Error("nothing published satisfies nothing")
	}
}

// writeRecipe puts a package.yml under the pantry's projects/ tree.
func writeGapRecipe(t *testing.T, root, proj, body string) {
	t.Helper()
	dir := filepath.Join(root, "projects", proj)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const minimal = "distributable:\n  url: https://x/v{{version}}.tgz\nversions:\n  github: a/b/tags\nbuild: make\n"

func TestUnsatisfiableCountsBothDepKinds(t *testing.T) {
	root := t.TempDir()
	// A runtime dep that cannot be served, on a project we DO publish.
	writeGapRecipe(t, root, "a.org", minimal+"dependencies:\n  openssl.org: ^1.1\n")
	// A BUILD dep, which counts the same: it stops the build just as dead.
	writeGapRecipe(t, root, "b.org", "distributable:\n  url: https://x/v{{version}}.tgz\nversions:\n  github: a/b/tags\nbuild:\n  dependencies:\n    openssl.org: ^1.1\n  script: make\n")
	// Satisfied, unconstrained, and a project nothing is published for: none
	// of the three is a version-line gap.
	writeGapRecipe(t, root, "c.org", minimal+"dependencies:\n  openssl.org: ^3\n  zlib.net: '*'\n  never.published: ^9\n")

	have := map[string][]string{"openssl.org": {"3.5.0"}, "zlib.net": {"1.3.2"}}
	got, absent, err := unsatisfiable(root, linuxTarget(), have)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want exactly the openssl ^1.1 pair", got)
	}
	blocking := got["openssl.org ^1.1"]
	if len(blocking) != 2 || blocking[0] != "a.org" || blocking[1] != "b.org" {
		t.Fatalf("blocking = %v, want a.org and b.org", blocking)
	}
	// never.published is a MISSING PROJECT, not a missing version line, and
	// lands in the other bucket rather than being dropped.
	if by := absent["never.published"]; len(by) != 1 || by[0] != "c.org" {
		t.Fatalf("absent = %v, want c.org blocked on never.published", absent)
	}
}

func TestUnsatisfiableSkipsWhatItCannotJudge(t *testing.T) {
	root := t.TempDir()
	writeGapRecipe(t, root, "broken.org", "this: is not: a recipe:\n")
	// A stray file that is not a package.yml.
	if err := os.WriteFile(filepath.Join(root, "projects", "broken.org", "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, err := unsatisfiable(root, linuxTarget(), map[string][]string{"openssl.org": {"3.5.0"}})
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v — an unparseable recipe is the schema gate's problem", got, err)
	}
}

func TestUnsatisfiableWalkErrors(t *testing.T) {
	root := t.TempDir()
	writeGapRecipe(t, root, "a.org", minimal+"dependencies:\n  openssl.org: ^1.1\n")
	have := map[string][]string{"openssl.org": {"3.5.0"}}

	t.Run("walk fails", func(t *testing.T) {
		defer restoreWalk(filepathWalkDir)
		boom := errors.New("boom")
		filepathWalkDir = func(string, fs.WalkDirFunc) error { return boom }
		if _, _, err := unsatisfiable(root, linuxTarget(), have); !errors.Is(err, boom) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("entry error is skipped", func(t *testing.T) {
		defer restoreWalk(filepathWalkDir)
		filepathWalkDir = func(_ string, fn fs.WalkDirFunc) error {
			return fn("whatever", nil, errors.New("stat failed"))
		}
		got, _, err := unsatisfiable(root, linuxTarget(), have)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("unreadable recipe is skipped", func(t *testing.T) {
		defer restoreReadFileBK(osReadFile)
		osReadFile = func(string) ([]byte, error) { return nil, errors.New("nope") }
		got, _, err := unsatisfiable(root, linuxTarget(), have)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("path outside the root is skipped", func(t *testing.T) {
		defer restoreWalk(filepathWalkDir)
		filepathWalkDir = func(_ string, fn fs.WalkDirFunc) error {
			return fn("relative/package.yml", fakeEntry{"package.yml"}, nil)
		}
		got, _, err := unsatisfiable(root, linuxTarget(), have)
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
}

func TestReportGaps(t *testing.T) {
	var b strings.Builder
	reportGaps(&b, map[string][]string{
		"python.org ~3.12": {"c.org", "a.org", "b.org", "d.org"},
		"go.dev ~1.21":     {"e.org"},
		"nodejs.org ^20":   {"f.org"},
	}, "linux/x86-64", 2)
	out := b.String()
	if !strings.Contains(out, "3 unsatisfiable (project, constraint) pair(s), blocking 6") {
		t.Errorf("totals wrong:\n%s", out)
	}
	// Worst first, examples sorted and capped at three.
	if !strings.Contains(out, "4  python.org ~3.12") || !strings.Contains(out, "e.g. a.org, b.org, c.org") {
		t.Errorf("ranking or examples wrong:\n%s", out)
	}
	if strings.Contains(out, "d.org") {
		t.Errorf("the example list must stop at three:\n%s", out)
	}
	// The cut is announced rather than silent: a truncated report that looks
	// complete is how a worklist gets believed.
	if !strings.Contains(out, "… and 1 more pair(s)") {
		t.Errorf("the cut is not announced:\n%s", out)
	}
	// Ties break by name, and --top 0 lists everything.
	var all strings.Builder
	reportGaps(&all, map[string][]string{"b.org ^1": {"x"}, "a.org ^1": {"y"}}, "linux/x86-64", 0)
	if strings.Index(all.String(), "a.org ^1") > strings.Index(all.String(), "b.org ^1") {
		t.Errorf("ties are not broken by name:\n%s", all.String())
	}
}

func TestRunDepgaps(t *testing.T) {
	root := t.TempDir()
	writeGapRecipe(t, root, "a.org", minimal+"dependencies:\n  openssl.org: ^1.1\n")
	reg := filepath.Join(root, "r.json")
	if err := os.WriteFile(reg, []byte(regJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb strings.Builder
	code := runDepgaps([]string{"--pantry", root, "--overrides", "", "--registry", reg}, &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "openssl.org ^1.1") {
		t.Errorf("the gap is not reported:\n%s", out.String())
	}

	// A bad flag is a usage error, not a silent empty report.
	if code := runDepgaps([]string{"--nope"}, io.Discard, io.Discard); code != 2 {
		t.Errorf("code=%d, want 2", code)
	}
	// A registry that cannot be read must fail, not rank nothing.
	if code := runDepgaps([]string{"--pantry", root, "--overrides", "", "--registry", "/nope.json"}, io.Discard, io.Discard); code != 1 {
		t.Errorf("code=%d, want 1", code)
	}
	// An override that does not apply is skip-loud by design, so the run
	// continues — but it must SAY so, because the ranking is then a claim about
	// a pantry the factory will not build.
	bad := filepath.Join(root, "badpatch")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "x.patch"), []byte("not a diff at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	var skipErr strings.Builder
	if code := runDepgaps([]string{"--pantry", root, "--overrides", bad, "--registry", reg}, io.Discard, &skipErr); code != 0 {
		t.Errorf("code=%d, want 0", code)
	}
	if !strings.Contains(skipErr.String(), "did NOT apply") {
		t.Errorf("a skipped override was not surfaced: %q", skipErr.String())
	}

	// The one shape Apply itself refuses: a directory whose name is not a valid
	// glob pattern.
	if code := runDepgaps([]string{"--pantry", root, "--overrides", "[", "--registry", reg}, io.Discard, io.Discard); code != 1 {
		t.Errorf("code=%d, want 1", code)
	}
}

func TestUnsatisfiableWalkPropagatesEntryReadError(t *testing.T) {
	// The walk itself returning an error from deep inside is surfaced, not
	// swallowed: a partial ranking read as complete is worse than none.
	defer restoreWalk(filepathWalkDir)
	boom := errors.New("deep")
	filepathWalkDir = func(_ string, fn fs.WalkDirFunc) error {
		_ = fn("x", fakeEntry{"package.yml"}, nil)
		return boom
	}
	if _, _, err := unsatisfiable(t.TempDir(), linuxTarget(), nil); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

type fakeEntry struct{ name string }

func (f fakeEntry) Name() string               { return f.name }
func (f fakeEntry) IsDir() bool                { return false }
func (f fakeEntry) Type() fs.FileMode          { return 0 }
func (f fakeEntry) Info() (fs.FileInfo, error) { return nil, nil }

func restoreWalk(f func(string, fs.WalkDirFunc) error) { filepathWalkDir = f }
func restoreReadFileBK(f func(string) ([]byte, error)) { osReadFile = f }

func linuxTarget() target.Target { return target.Target{Platform: "linux", Arch: "x86-64"} }

// TestDepgapsIsReachableFromMain: a subcommand nothing dispatches to is a
// subcommand nobody can run.
func TestDepgapsIsReachableFromMain(t *testing.T) {
	code, _, errb := run2(t, "depgaps", "--registry", "/definitely/not/here.json")
	if code != 1 {
		t.Fatalf("code=%d, want 1 (the command ran and failed on its input)", code)
	}
	if !strings.Contains(errb, "depgaps:") {
		t.Errorf("stderr does not come from depgaps: %q", errb)
	}
}

// TestRunDepgapsSurfacesAWalkFailure: a ranking cut short by an unreadable tree
// must fail, not print a short list that reads as the whole answer.
func TestRunDepgapsSurfacesAWalkFailure(t *testing.T) {
	root := t.TempDir()
	reg := filepath.Join(root, "r.json")
	if err := os.WriteFile(reg, []byte(regJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	defer restoreWalk(filepathWalkDir)
	filepathWalkDir = func(string, fs.WalkDirFunc) error { return errors.New("tree gone") }

	var errb strings.Builder
	if code := runDepgaps([]string{"--pantry", root, "--overrides", "", "--registry", reg}, io.Discard, &errb); code != 1 {
		t.Fatalf("code=%d, want 1", code)
	}
	if !strings.Contains(errb.String(), "tree gone") {
		t.Errorf("the cause is not reported: %q", errb.String())
	}
}

// TestReportAbsent: the second half of the front, ranked the same way, and
// with a recipe counted once even when it names the project in both its
// runtime and its build dependencies.
func TestReportAbsent(t *testing.T) {
	var b strings.Builder
	reportAbsent(&b, map[string][]string{
		"rust-lang.org": {"a.org", "a.org", "b.org", "c.org", "d.org"},
		"openjdk.org":   {"e.org"},
		"ruby-lang.org": {"f.org"},
	}, "linux/x86-64", 2)
	out := b.String()
	if !strings.Contains(out, "3 project(s) with NOTHING published, blocking 6") {
		t.Errorf("totals wrong (a.org must count once):\n%s", out)
	}
	if !strings.Contains(out, "4  rust-lang.org") {
		t.Errorf("ranking wrong:\n%s", out)
	}
	if !strings.Contains(out, "e.g. a.org, b.org, c.org") || strings.Contains(out, "d.org") {
		t.Errorf("examples wrong or uncapped:\n%s", out)
	}
	if !strings.Contains(out, "… and 1 more project(s)") {
		t.Errorf("the cut is not announced:\n%s", out)
	}
	// --top 0 lists everything, ties broken by name.
	var all strings.Builder
	reportAbsent(&all, map[string][]string{"b.org": {"x"}, "a.org": {"y"}}, "linux/x86-64", 0)
	if strings.Index(all.String(), "a.org") > strings.Index(all.String(), "b.org") {
		t.Errorf("ties are not broken by name:\n%s", all.String())
	}
}

// TestRunDepgapsPrintsBothHalves: the command reports the version lines AND
// the projects nothing is published for — reporting only the first sends the
// operator at the smaller half.
func TestRunDepgapsPrintsBothHalves(t *testing.T) {
	root := t.TempDir()
	writeGapRecipe(t, root, "a.org", minimal+"dependencies:\n  openssl.org: ^1.1\n  rust-lang.org: '*'\n")
	reg := filepath.Join(root, "r.json")
	if err := os.WriteFile(reg, []byte(regJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if code := runDepgaps([]string{"--pantry", root, "--overrides", "", "--registry", reg}, &out, io.Discard); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out.String(), "openssl.org ^1.1") {
		t.Errorf("the version-line half is missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "NOTHING published") || !strings.Contains(out.String(), "rust-lang.org") {
		t.Errorf("the missing-project half is missing:\n%s", out.String())
	}
}

// A recipe that declares it does not target this platform is not a gap on it.
// Without this, kernel.org/linux and github.com/vmware/tdnf — both
// `platforms: linux` — put rpm.org/rpm, opensuse.org/libsolv, elfutils.org and
// kernel.org/libcap into a darwin/aarch64 ranking, where none of them will ever
// be asked for.
func TestUnsatisfiableSkipsRecipesThatDoNotTargetThePlatform(t *testing.T) {
	root := t.TempDir()
	writeGapRecipe(t, root, "kernel.org/linux",
		minimal+"platforms: linux\ndependencies:\n  elfutils.org: '*'\n  openssl.org: ^1.1\n")
	writeGapRecipe(t, root, "portable.org",
		minimal+"dependencies:\n  elfutils.org: '*'\n  openssl.org: ^1.1\n")

	have := map[string][]string{"openssl.org": {"3.5.0"}}
	darwin := target.Target{Platform: "darwin", Arch: "aarch64"}
	got, absent, err := unsatisfiable(root, darwin, have)
	if err != nil {
		t.Fatal(err)
	}
	// Only the portable recipe counts, on both halves of the answer.
	if want := []string{"portable.org"}; !equalStrings(got["openssl.org ^1.1"], want) {
		t.Errorf("version-line gap = %v, want %v", got["openssl.org ^1.1"], want)
	}
	if want := []string{"portable.org"}; !equalStrings(absent["elfutils.org"], want) {
		t.Errorf("absent-project gap = %v, want %v", absent["elfutils.org"], want)
	}

	// The same pantry on linux counts both, which is the control: the recipe is
	// skipped for the platform it excludes, not dropped outright.
	got, absent, err = unsatisfiable(root, linuxTarget(), have)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["openssl.org ^1.1"]) != 2 || len(absent["elfutils.org"]) != 2 {
		t.Errorf("on linux: got %v / %v, want both recipes counted",
			got["openssl.org ^1.1"], absent["elfutils.org"])
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
