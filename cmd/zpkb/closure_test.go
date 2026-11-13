package main

import (
	"bytes"
	"errors"
	"github.com/go-zpkg/zpkb/logical"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// writeClosureRecipe drops a package.yml under <pantry>/projects/<proj>/.
func writeClosureRecipe(t *testing.T, pantry, proj, yaml string) {
	t.Helper()
	dir := filepath.Join(pantry, "projects", proj)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.yml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunClosure(t *testing.T) {
	p := t.TempDir()
	// app -> lib -> (nothing); app also -> missing.org (no recipe → skipped)
	writeClosureRecipe(t, p, "app.org", "dependencies:\n  lib.org: '*'\n  missing.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, p, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")

	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	lines := strings.Fields(out.String())
	// topological: lib.org before app.org; missing.org absent (no recipe).
	if len(lines) != 2 || lines[0] != "lib.org" || lines[1] != "app.org" {
		t.Errorf("order = %v, want [lib.org app.org]", lines)
	}
	if !strings.Contains(errb.String(), "skip missing.org") {
		t.Errorf("expected skip note for missing.org, got %q", errb.String())
	}
	// idempotent revisit: depending on app twice must not duplicate.
	out.Reset()
	errb.Reset()
	runClosure([]string{"--pantry", p, "app.org", "app.org"}, &out, &errb)
	if n := len(strings.Fields(out.String())); n != 2 {
		t.Errorf("cycle/dup guard: got %d lines, want 2", n)
	}
}

func TestRunClosureFlagError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runClosure([]string{"-nope"}, &out, &errb); code != 2 {
		t.Errorf("bad flag code=%d, want 2", code)
	}
}

func TestRunClosureEnvFallback(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "leaf.org", "versions:\n  github: a/leaf/tags\nbuild: make\n")
	t.Setenv("PANTRY", p)
	t.Setenv("PLATFORM", "linux/aarch64")
	var out, errb bytes.Buffer
	if code := runClosure([]string{"leaf.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if strings.TrimSpace(out.String()) != "leaf.org" {
		t.Errorf("env-fallback out = %q", out.String())
	}
}

func TestDepName(t *testing.T) {
	for spec, want := range map[string]string{
		"openssl.org@^1.1":               "openssl.org",
		"zlib.net":                       "zlib.net",
		"invisible-island.net/ncurses^6": "invisible-island.net/ncurses",
		"cmake.org~3.30":                 "cmake.org",
		"gnu.org/gmp>=6":                 "gnu.org/gmp",
		"llvm.org<19":                    "llvm.org",
		"zlib.net=1.3.1":                 "zlib.net",
	} {
		if got := depName(spec); got != want {
			t.Errorf("depName(%q)=%q want %q", spec, got, want)
		}
	}
}

// TestRunClosureRangeConstrainedDep pins the defect that hid gnu.org/readline's
// ncurses: DepSpecs renders `dependencies: {invisible-island.net/ncurses: ^6}`
// as "…/ncurses^6", and a closure that splits on "@" alone looked for a project
// literally named "…/ncurses^6", skipped it, and built readline with no ncurses
// in scope — `ld.lld: unable to find library -lncursesw`, three layers away.
func TestRunClosureRangeConstrainedDep(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "app.org", "dependencies:\n  lib.org: ^6\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, p, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")

	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/aarch64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if lines := strings.Fields(out.String()); len(lines) != 2 || lines[0] != "lib.org" || lines[1] != "app.org" {
		t.Errorf("order = %v, want [lib.org app.org]", lines)
	}
	if errb.Len() != 0 {
		t.Errorf("a caret-constrained dep must resolve, not be skipped: %q", errb.String())
	}
}

// TestClosureDispatch covers the main-loop `case "closure"` route.
func TestClosureDispatch(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "leaf.org", "versions:\n  github: a/leaf/tags\nbuild: make\n")
	code, out, errs := run2(t, "closure", "--pantry", p, "leaf.org")
	if code != 0 {
		t.Fatalf("dispatch closure code=%d err=%q", code, errs)
	}
	if strings.TrimSpace(out) != "leaf.org" {
		t.Errorf("dispatch closure out=%q", out)
	}
}

// writeClosureRecipeNamed writes a recipe under a chosen filename, for tests
// that care which front-end reads it.
func writeClosureRecipeNamed(t *testing.T, pantry, proj, name, body string) {
	t.Helper()
	dir := filepath.Join(pantry, "projects", proj)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The edge that started this: perl.org NEEDs libcrypt.so.1, our overlay says
// so and upstream's recipe does not. The factory's own walk read the pantry
// alone, so the provider was never built — while every consumer resolved it
// from the overlay and found nothing in the registry.
func TestClosureOfSeesAnOverlayOnlyDependency(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeClosureRecipe(t, pantry, "perl.org", "dependencies:\n  gnu.org/gdbm: '*'\n")
	writeClosureRecipe(t, overlay, "perl.org", "dependencies:\n  github.com/besser82/libxcrypt: '*'\n")
	writeClosureRecipe(t, pantry, "gnu.org/gdbm", "build: make\n")
	writeClosureRecipe(t, pantry, "github.com/besser82/libxcrypt", "build: make\n")

	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	order, _, _ := closureOf(nil, overlay, pantry, tgt, []string{"perl.org"}, func(string) {})
	for _, want := range []string{"github.com/besser82/libxcrypt", "gnu.org/gdbm", "perl.org"} {
		if !slices.Contains(order, want) {
			t.Errorf("order = %v, missing %s", order, want)
		}
	}
	// Both halves, not the overlay winning: the pantry's own dependency is
	// what the BUILD will need in its environment.
	if len(order) != 3 {
		t.Errorf("order = %v, want exactly the three", order)
	}

	// Without the overlay this is the walk it replaces, blind spot and all.
	if order, _, _ := closureOf(nil, "", pantry, tgt, []string{"perl.org"}, func(string) {}); slices.Contains(order, "github.com/besser82/libxcrypt") {
		t.Errorf("a pantry-only walk cannot see the overlay's edge: %v", order)
	}
}

// A constraint in either half is a constraint something will ask for:
// surrealdb.com asks rust-lang.org for ">=1.60" in the overlay and "~1.95" in
// the patched pantry, and a version satisfying only one of them leaves the
// other asking for something nothing built.
func TestClosureOfCollectsDemandsFromBothHalves(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeClosureRecipe(t, pantry, "app.org", "dependencies:\n  lib.org: ~1.95\n")
	writeClosureRecipe(t, overlay, "app.org", "dependencies:\n  lib.org: '>=1.60'\n")
	writeClosureRecipe(t, pantry, "lib.org", "build: make\n")

	_, demands, _ := closureOf(nil, overlay, pantry, target.Target{Platform: "linux", Arch: "x86-64"},
		[]string{"app.org"}, func(string) {})
	got := demands["lib.org"]
	slices.Sort(got)
	if len(got) != 2 || got[0] != ">=1.60" || got[1] != "~1.95" {
		t.Errorf("demands = %v, want both halves", got)
	}
}

// A project only the overlay carries is still a project, and a recipe that
// exists in either half and does not parse is never skipped quietly: the walk
// would plan a build around a recipe it could not read.
func TestClosureRecipes(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeClosureRecipe(t, overlay, "only.example", "build: make\n")
	if recs, err := closureRecipes(nil, overlay, pantry, "only.example"); err != nil || len(recs) != 1 {
		t.Errorf("overlay-only: %d recipe(s), %v", len(recs), err)
	}
	if _, err := closureRecipes(nil, overlay, pantry, "absent.example"); !errors.Is(err, recipefile.ErrNoRecipe) {
		t.Errorf("absent everywhere: %v", err)
	}
	writeClosureRecipe(t, overlay, "broken.example", "dependencies: [\n")
	if _, err := closureRecipes(nil, overlay, pantry, "broken.example"); err == nil || errors.Is(err, recipefile.ErrNoRecipe) {
		t.Errorf("a recipe that exists and does not parse must be reported: %v", err)
	}
	// With no overlay it is the pantry-only loader it replaces.
	writeClosureRecipe(t, pantry, "plain.example", "build: make\n")
	if recs, err := closureRecipes(nil, "", pantry, "plain.example"); err != nil || len(recs) != 1 {
		t.Errorf("pantry-only: %d recipe(s), %v", len(recs), err)
	}
}

// `bk closure` reads the same logical overrides the factory does, so the order
// it prints is the order that would be built.
func TestRunClosureWithLogicalOverrides(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "app.org", "dependencies:\n  lib.org: '*'\nbuild: make\n")
	writeClosureRecipe(t, p, "lib.org", "build: make\n")

	ovDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ovDir, "app.hcl"), []byte(`
project = "app.org"
why     = "it links zlib and upstream does not say so"
merge {
  dependencies = { "zlib.net" = "^1" }
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeClosureRecipe(t, p, "zlib.net", "build: make\n")

	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--overrides", ovDir, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("code, stderr = %s", errb.String())
	}
	if !strings.Contains(out.String(), "zlib.net") {
		t.Errorf("the override's dependency is not in the closure:\n%s", out.String())
	}

	// A broken one stops the walk rather than describing a build nobody
	// performs.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "x.hcl"), []byte("project = "), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := runClosure([]string{"--pantry", p, "--overrides", bad, "app.org"}, &out, &errb); code != 2 {
		t.Errorf("code = %d, want 2; stderr = %s", code, errb.String())
	}
}

// An overlay recipe that EXISTS and does not parse must stop the walk, not
// fall through to the pantry: falling through describes a build from something
// other than what the overlay says, silently.
func TestClosureGraphRefusesAnUnparsableOverlayRecipe(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeClosureRecipe(t, pantry, "app.org", "build: make\n")
	writeClosureRecipeNamed(t, overlay, "app.org", "package.hcl", "distributable {")

	var errb bytes.Buffer
	g := newClosureGraph(nil, pantry, target.Target{Platform: "linux", Arch: "x86-64"}, true,
		func(s string) { errb.WriteString(s + "\n") })
	g.overlay = overlay
	g.visit("app.org")
	if !strings.Contains(errb.String(), "app.org") {
		t.Errorf("the walk must say which recipe it could not read: %q", errb.String())
	}
	if len(g.order) != 0 {
		t.Errorf("a recipe it could not read must not enter the order: %v", g.order)
	}
}

// And the logical overrides reach the GRAPH walk too — `bk closure --build` is
// the tool a person runs to work out what the factory will do, so the two have
// to read a recipe the same way. The first draft of this wiring gave the set to
// closureOf and not to the graph, which is the very asymmetry go-zpkg/bk#224
// had just been written to remove.
func TestClosureGraphAppliesLogicalOverrides(t *testing.T) {
	pantry := t.TempDir()
	writeClosureRecipe(t, pantry, "app.org", "build: make\n")
	writeClosureRecipe(t, pantry, "zlib.net", "build: make\n")

	ovDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ovDir, "app.hcl"), []byte(`
project = "app.org"
why     = "it links zlib and upstream does not say so"
merge { dependencies = { "zlib.net" = "^1" } }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := logical.LoadDir(ovDir)
	if err != nil {
		t.Fatal(err)
	}
	g := newClosureGraph(set, pantry, target.Target{Platform: "linux", Arch: "x86-64"}, true, nil)
	g.visit("app.org")
	if !slices.Contains(g.order, "zlib.net") {
		t.Errorf("the override's dependency is not in the graph: %v", g.order)
	}
}

// TestClosureFailsOnARootItCannotRead. A dependency with no recipe is skipped
// on purpose; a project that was ASKED FOR is not the same thing, and the walk
// used to skip both by the same line and exit 0.
//
// The witness is the shape that caught me on 2026-09-28: zsh does not
// word-split an unquoted expansion, so all 76 seed projects went in as ONE
// argument. The walk printed nothing, exited 0, and I nearly wrote the empty
// answer down as a measurement.
func TestClosureFailsOnARootItCannotRead(t *testing.T) {
	pan := t.TempDir()
	writeClosureRecipe(t, pan, "app.org", "dependencies:\n  gone.org: '*'\nbuild: make\n")

	// A DEPENDENCY with no recipe is still a skip: it resolves from upstream
	// dist at build time, and this is the premise of the case below.
	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", pan, "--platform", "linux/x86-64", "app.org"}, &out, &errb); code != 0 {
		t.Fatalf("a missing dependency must not fail the walk: code = %d, %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "app.org") {
		t.Errorf("order = %q", out.String())
	}

	for _, withBuild := range []bool{false, true} {
		args := []string{"--pantry", pan, "--platform", "linux/x86-64"}
		if withBuild {
			args = append(args, "--build")
		}
		// One argument holding two names: no recipe is called that.
		out.Reset()
		errb.Reset()
		if code := runClosure(append(args, "app.org gone.org"), &out, &errb); code == 0 {
			t.Errorf("--build=%v: a root nobody can read must fail, got 0 and %q", withBuild, out.String())
		}
		if !strings.Contains(errb.String(), "asked for and not read") {
			t.Errorf("--build=%v: stderr must name it: %q", withBuild, errb.String())
		}
		// And nothing is printed, so a caller cannot mistake it for an answer.
		if out.Len() != 0 {
			t.Errorf("--build=%v: printed an order anyway: %q", withBuild, out.String())
		}
	}
}

// The seed order writes `project@constraint`, and until now only two of its
// three readers understood it: pinning gnu.org/gawk@~5.3 made the closure
// gate report it as a project nobody has.
func TestClosureRootsAcceptTheOrdersPinnedForm(t *testing.T) {
	var said []string
	got, pins := closureRoots([]string{"gnu.org/gawk@~5.3", "zlib.net", "perl.org@~5.44", "tcl-lang.org@=9.0.4"},
		func(s string) { said = append(said, s) })
	want := []string{"gnu.org/gawk", "zlib.net", "perl.org", "tcl-lang.org"}
	// The constraints come BACK, keyed by project: the walk cannot use them
	// but whoever resolves a root can, and a root has no dependent to speak
	// for it. Without this they were stripped and lost in the same line.
	for proj, c := range map[string]string{"gnu.org/gawk": "~5.3", "perl.org": "~5.44", "tcl-lang.org": "=9.0.4"} {
		if pins[proj] != c {
			t.Errorf("pins[%q] = %q, want %q", proj, pins[proj], c)
		}
	}
	if _, ok := pins["zlib.net"]; ok {
		t.Errorf("an unconstrained root was given a constraint: %q", pins["zlib.net"])
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("root %d = %q, want %q", i, got[i], want[i])
		}
	}
	// Said out loud: the walk does not apply the constraint, and a reader
	// must not assume it did.
	if len(said) != 1 || !strings.Contains(said[0], "3 root(s) carry a version constraint") {
		t.Errorf("the dropped pins were not named: %v", said)
	}
}

// A bare list says nothing, and a leading '@' is not a pin — it is a project
// name we cannot read, and cutting at index 0 would turn it into the empty
// string and then into every recipe in the pantry.
func TestClosureRootsSayNothingWhenNothingIsPinned(t *testing.T) {
	var said []string
	got, pins := closureRoots([]string{"zlib.net", "@odd"}, func(s string) { said = append(said, s) })
	if len(got) != 2 || got[0] != "zlib.net" || got[1] != "@odd" {
		t.Errorf("got %v", got)
	}
	if len(pins) != 0 {
		t.Errorf("a leading '@' was read as a constraint: %v", pins)
	}
	if len(said) != 0 {
		t.Errorf("said something about nothing: %v", said)
	}
}

// warn may be nil.
func TestClosureRootsToleratesNoWarner(t *testing.T) {
	got, pins := closureRoots([]string{"a@1"}, nil)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("got %v", got)
	}
	if pins["a"] != "1" {
		t.Errorf("the constraint was lost when there was no warner: %v", pins)
	}
}

// End to end: the pinned form reaches runClosure, the project is READ rather
// than reported missing, and the dropped constraint is named on stderr.
func TestRunClosureReadsAPinnedRoot(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "gnu.org/gawk", "versions:\n  github: a/gawk/tags\nbuild: make\n")

	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "gnu.org/gawk@~5.3"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	if got := strings.TrimSpace(out.String()); got != "gnu.org/gawk" {
		t.Errorf("order = %q, want gnu.org/gawk", got)
	}
	if strings.Contains(errb.String(), "not read") {
		t.Errorf("a pinned root was reported missing: %q", errb.String())
	}
	// It names the pin AND says which half of the resolution honours it: the
	// root itself does, the walk does not. The earlier wording said only the
	// second, which became misleading the moment `bk lock` started applying
	// a root's own constraint.
	if !strings.Contains(errb.String(), "carry a version constraint") ||
		!strings.Contains(errb.String(), "NOT propagated through the walk") {
		t.Errorf("the dropped pin was not named: %q", errb.String())
	}
}

// `bk closure <a set>` resolves the packages the set names. The command is
// the only place the expansion is wired, so without this the warn callback
// it passes is never run — which the per-block coverage gate catches even
// though the rounded total reads 100%.
func TestRunClosureResolvesASet(t *testing.T) {
	p := t.TempDir()
	writeClosureRecipe(t, p, "app.org", "dependencies:\n  lib.org: '*'\nversions:\n  github: a/app/tags\nbuild: make\n")
	writeClosureRecipe(t, p, "lib.org", "versions:\n  github: a/lib/tags\nbuild: make\n")
	writeClosureRecipe(t, p, "acme.org/every", "members:\n  app.org: '*'\n")

	var out, errb bytes.Buffer
	if code := runClosure([]string{"--pantry", p, "--platform", "linux/x86-64", "acme.org/every"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
	// The same order naming app.org directly gives: a set is expanded at the
	// root and nothing downstream knows it happened.
	if got := strings.Fields(out.String()); len(got) != 2 || got[0] != "lib.org" || got[1] != "app.org" {
		t.Errorf("order = %v, want [lib.org app.org]", got)
	}
	// And it says so on stderr, because a root that silently became three
	// roots is a closure nobody can check.
	if !strings.Contains(errb.String(), "names 1 member(s)") {
		t.Errorf("the expansion was silent: %q", errb.String())
	}
}
