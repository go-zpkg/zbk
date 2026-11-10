package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/buildscript"
	"github.com/go-zpkg/zbk/target"
	"mvdan.cc/sh/v3/interp"
)

// testbed points bk's path computation at a scratch checkout, so a test never
// reads or writes the developer's real ~/.pkgx or XDG data home.
//
// ⛔ IT ALSO INSTALLS THE BUILD UNDER TEST. `zbk test` runs against a build
// and no longer composes `<store>/<project>/v<version>` to find it — there is
// no such directory any more — so it asks the store, and a store with nothing
// in it makes every case here fail for the one uninteresting reason. The
// refusal has its own test below; these want a build to point at.
func testTestbed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ZPKG_PANTRY_DIR", dir)
	t.Setenv("ZPKG_DIR", filepath.Join(dir, "pkgx"))
	installTestBuild(t, filepath.Join(dir, "pkgx"), "proj.org", "1.2.3")
	return dir
}

// installTestBuild makes the directory an install makes: hashed, and nothing
// beside it that names the version alone.
func installTestBuild(t *testing.T, store, project, version string) string {
	t.Helper()
	v := bottle.Ver{Raw: version}
	hash := bottle.StoreHash(v, "digest:"+project+"@"+version, "")
	if err := os.MkdirAll(bottle.StoreBuildPrefix(store, project, v, hash), 0o755); err != nil {
		t.Fatal(err)
	}
	return hash
}

// writeTestRecipe drops a package.yml in its own project directory, as a pantry
// holds one, and returns its path.
func writeTestRecipe(t *testing.T, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "proj.org")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "package.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// stubRun replaces the script runner and records what it was handed.
func stubRun(t *testing.T, err error) *string {
	t.Helper()
	var got string
	prev := testRun
	testRun = func(scriptPath string, _ []string) error {
		got = scriptPath
		return err
	}
	t.Cleanup(func() { testRun = prev })
	return &got
}

// requireNonRootHere skips a case whose whole mechanism is a permission
// root does not have. The repository already does this in fixup and builder;
// the CI runner is unprivileged, so the branch stays covered there.
func requireNonRootHere(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: the permission this case relies on does not apply")
	}
}

const okRecipe = "versions:\n  - 1.2.3\nbuild: make\ntest: proj --version | grep 1.2.3\n"

func TestRunTestUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no project", []string{"--recipe", "/x/package.yml"}},
		{"no recipe", []string{"proj.org"}},
		{"bad flag", []string{"--nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := runTest(tc.args, &out, &errOut); code != 2 {
				t.Errorf("want 2, got %d (%s)", code, errOut.String())
			}
		})
	}
}

func TestRunTestUnreadableRecipe(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runTest([]string{"--recipe", filepath.Join(t.TempDir(), "absent.yml"), "proj.org"}, &out, &errOut)
	if code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
	if !strings.Contains(errOut.String(), "error:") {
		t.Errorf("no error said: %q", errOut.String())
	}
}

func TestRunTestUnparseableRecipe(t *testing.T) {
	p := writeTestRecipe(t, "versions: [1.0.0]\nbuild: make\ntest: 3\nthis is: not: yaml:\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want 1, got %d (%s)", code, errOut.String())
	}
}

// The heart of go-zpkg/bk#162: a recipe with no test block has not passed.
// Exit 3 is neither 0 nor 1 so a caller cannot collapse the three outcomes.
func TestRunTestSaysWhenThereIsNoTestBlock(t *testing.T) {
	testTestbed(t)
	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\n")
	var out, errOut bytes.Buffer
	code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut)
	if code != exitNoTest {
		t.Errorf("want %d, got %d", exitNoTest, code)
	}
	if code == 0 || code == 1 {
		t.Error("a missing test must not read as a pass or a failure")
	}
	if !strings.Contains(out.String(), "declares no test") {
		t.Errorf("unclear message: %q", out.String())
	}
}

func TestRunTestUnresolvableTarget(t *testing.T) {
	testTestbed(t)
	t.Setenv("ZBK_TARGET", "not-a-target")
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
}

func TestRunTestUnresolvableVersion(t *testing.T) {
	testTestbed(t)
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	code := runTest([]string{"--recipe", p, "--version", "9.9.9", "proj.org"}, &out, &errOut)
	// A version this recipe cannot resolve is not a package that failed its
	// test — it is a test that never ran.
	if code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
	if !strings.Contains(errOut.String(), "resolve version") {
		t.Errorf("want the version step named: %q", errOut.String())
	}
}

func TestRunTestPasses(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "PASS proj.org 1.2.3") {
		t.Errorf("no PASS line: %q", out.String())
	}
	script, err := os.ReadFile(*got)
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	// The exact version, not a bare project name: a green line has to be
	// about the build the operator named.
	if !strings.Contains(s, `"+proj.org@1.2.3"`) {
		t.Errorf("the package is not pinned in the eval:\n%s", s)
	}
	if !strings.Contains(s, "proj --version | grep 1.2.3") {
		t.Errorf("the recipe's test did not reach the script:\n%s", s)
	}
}

func TestRunTestFails(t *testing.T) {
	testTestbed(t)
	stubRun(t, os.ErrPermission)
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 1 {
		t.Errorf("want 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "FAIL proj.org 1.2.3") {
		t.Errorf("no FAIL line: %q", errOut.String())
	}
}

// "Fresh sandbox" has to be true. A test block asserts on files it writes, so
// a leftover from the previous run can make a failed run look green.
func TestRunTestEmptiesTheSandbox(t *testing.T) {
	testTestbed(t)
	stubRun(t, nil)
	box := filepath.Join(t.TempDir(), "box")
	if err := os.MkdirAll(box, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(box, "yesterday.out")
	if err := os.WriteFile(stale, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "--sandbox", box, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("the previous run's artefact survived into the sandbox")
	}
}

// Beside the sandbox, not in it: the next run empties the sandbox, and a test
// that lists its working directory must not find our script there.
func TestRunTestWritesTheScriptOutsideTheSandbox(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	box := filepath.Join(t.TempDir(), "box")
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "--sandbox", box, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	if strings.HasPrefix(*got, box+string(os.PathSeparator)) {
		t.Errorf("script %q is inside the sandbox %q", *got, box)
	}
	entries, err := os.ReadDir(box)
	if err != nil {
		t.Fatal(err)
	}
	// The sandbox holds the recipe's own files and nothing of ours.
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".test.sh") {
			t.Errorf("our script is in the sandbox: %s", e.Name())
		}
	}
}

func TestRunTestReportsASandboxItCannotClear(t *testing.T) {
	requireNonRootHere(t)
	testTestbed(t)
	parent := filepath.Join(t.TempDir(), "ro")
	box := filepath.Join(parent, "box")
	if err := os.MkdirAll(filepath.Join(box, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "--sandbox", box, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
	if !strings.Contains(errOut.String(), "clear sandbox") {
		t.Errorf("want the step named: %q", errOut.String())
	}
}

func TestRunTestReportsASandboxItCannotCreate(t *testing.T) {
	requireNonRootHere(t)
	testTestbed(t)
	// A read-only PARENT with nothing at the sandbox path: RemoveAll returns
	// nil (there is nothing to remove) and MkdirAll cannot create it. A file
	// in the parent's place would not do — RemoveAll fails on that with
	// ENOTDIR and the "clear" arm answers first.
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	code := runTest([]string{"--recipe", p, "--sandbox", filepath.Join(parent, "box"), "proj.org"}, &out, &errOut)
	if code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
	if !strings.Contains(errOut.String(), "create sandbox") {
		t.Errorf("want the step named: %q", errOut.String())
	}
}

func TestRunTestReportsAScriptItCannotWrite(t *testing.T) {
	testTestbed(t)
	stubRun(t, nil)
	dir := t.TempDir()
	box := filepath.Join(dir, "box")
	// Occupy the script's path with a DIRECTORY, which os.WriteFile cannot
	// overwrite.
	if err := os.MkdirAll(filepath.Join(dir, "box.test.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "--sandbox", box, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
}

func TestRunTestReportsAnUnrenderableTestBlock(t *testing.T) {
	testTestbed(t)
	// A guarded step with no `run`. The guard `>=1` matches version 1.2.3 on
	// every platform, so the step is kept and Generate then has nothing to
	// render — it refuses rather than emitting an empty command.
	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\ntest:\n  script:\n    - if: '>=1'\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want %d, got %d (%s)", exitCannotRun, code, errOut.String())
	}
}

// test.dependencies is its own map, and platform-keyed like the others.
func TestRunTestInstallsTheRecipesTestDependencies(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\n"+
		"test:\n  dependencies:\n    gnu.org/diffutils: ^3\n  script: diff a b\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	script, err := os.ReadFile(*got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), `"+gnu.org/diffutils^3"`) {
		t.Errorf("test dependency missing:\n%s", script)
	}
}

func TestTestDepSpecsIgnoresWhatIsNotADepMap(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	if got := testDepSpecs("just a script", tgt); got != nil {
		t.Errorf("a string test block has no dependencies, got %v", got)
	}
	if got := testDepSpecs(map[string]any{"script": "x"}, tgt); got != nil {
		t.Errorf("a map without dependencies has none, got %v", got)
	}
	if got := testDepSpecs(map[string]any{"dependencies": "nonsense"}, tgt); got != nil {
		t.Errorf("a non-map dependencies value yields none, got %v", got)
	}
}

// The dispatch arm. Without it `bk test` is unreachable from the command
// line, and nothing else in the suite goes through main's switch for it.
func TestTestCommandIsDispatched(t *testing.T) {
	// No --recipe, so runTest answers 2 (usage) — which is enough to prove
	// the arm was taken, and needs no recipe, pkgx or registry to do it.
	if code, _, errOut := run2(t, "test"); code != 2 {
		t.Errorf("code=%d, stderr=%q", code, errOut)
	}
}

// lookPath is asked because the script runs under a sanitized PATH. Both
// answers are exercised HERE rather than left to the machine: pkgx is on a
// developer's PATH and not on CI's, so leaving it implicit makes this branch
// covered in one place and not the other — which is how it first arrived red.
func TestRunTestResolvesPkgxToAnAbsolutePath(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	prev := lookPath
	lookPath = func(string) (string, error) { return "/opt/elsewhere/pkgx", nil }
	t.Cleanup(func() { lookPath = prev })

	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	script, err := os.ReadFile(*got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "/opt/elsewhere/pkgx") {
		t.Errorf("the resolved pkgx did not reach the script:\n%s", script)
	}
}

func TestRunTestKeepsTheGivenPkgxWhenItCannotBeResolved(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	prev := lookPath
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	t.Cleanup(func() { lookPath = prev })

	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "--zpkgx", "/my/zpkgx", "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	script, err := os.ReadFile(*got)
	if err != nil {
		t.Fatal(err)
	}
	// Kept as given: an explicit path still works and the original error
	// stays legible instead of being replaced by an empty string.
	if !strings.Contains(string(script), "/my/zpkgx") {
		t.Errorf("the given zpkgx was lost:\n%s", script)
	}
}

// Recipes name their fixtures by bare relative name (`cc test.c -lz`), so the
// sandbox has to hold them or the test fails on the tool.
func TestRunTestStagesTheRecipesOwnFiles(t *testing.T) {
	testTestbed(t)
	stubRun(t, nil)
	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\ntest: cc test.c\n")
	dir := filepath.Dir(p)
	if err := os.WriteFile(filepath.Join(dir, "test.c"), []byte("int main(){}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "entrypoint.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A SUBDIRECTORY of a recipe directory is another project, not a fixture.
	if err := os.MkdirAll(filepath.Join(dir, "minizip"), 0o755); err != nil {
		t.Fatal(err)
	}

	box := filepath.Join(t.TempDir(), "box")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "--sandbox", box, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(box, "test.c")); err != nil {
		t.Errorf("the fixture was not staged: %v", err)
	}
	fi, err := os.Stat(filepath.Join(box, "entrypoint.sh"))
	if err != nil {
		t.Fatalf("the executable fixture was not staged: %v", err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("the executable bit was lost: %v", fi.Mode())
	}
	if _, err := os.Stat(filepath.Join(box, "minizip")); !os.IsNotExist(err) {
		t.Error("a subproject directory was copied into the sandbox")
	}
	// The RECIPE is not a fixture. gnu.org/coreutils' test is
	// `touch test-file; test "$(ls -1)" = "test-file"`, and a package.yml in
	// the sandbox failed it on the s390x seed's first sweep.
	for _, n := range []string{"package.yml", "package.hcl"} {
		if _, err := os.Stat(filepath.Join(box, n)); !os.IsNotExist(err) {
			t.Errorf("%s was staged into the sandbox", n)
		}
	}
	// And nothing else of ours: a test that lists its working directory must
	// see only what the recipe put there.
	entries, err := os.ReadDir(box)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "entrypoint.sh" || names[1] != "test.c" {
		t.Errorf("sandbox holds %v, want exactly the two fixtures", names)
	}
}

func TestStageRecipeFilesReportsADirectoryItCannotRead(t *testing.T) {
	if err := stageRecipeFiles(filepath.Join(t.TempDir(), "absent"), t.TempDir()); err == nil {
		t.Error("want an error for a recipe directory that is not there")
	}
}

func TestStageRecipeFilesReportsAFileItCannotCopy(t *testing.T) {
	requireNonRootHere(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "secret"), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := stageRecipeFiles(src, t.TempDir()); err == nil {
		t.Error("want an error for a fixture that cannot be read")
	}
}

func TestStageRecipeFilesReportsASandboxItCannotWriteInto(t *testing.T) {
	requireNonRootHere(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.Chmod(dst, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dst, 0o755) })
	if err := stageRecipeFiles(src, dst); err == nil {
		t.Error("want an error for a sandbox that cannot be written")
	}
}

// A non-regular entry is skipped rather than followed.
func TestStageRecipeFilesSkipsWhatIsNotARegularFile(t *testing.T) {
	src := t.TempDir()
	if err := os.Symlink("/nowhere", filepath.Join(src, "dangling")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	dst := t.TempDir()
	if err := stageRecipeFiles(src, dst); err != nil {
		t.Fatalf("a dangling symlink must be skipped, not fatal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "dangling")); !os.IsNotExist(err) {
		t.Error("the symlink was copied")
	}
}

func TestRunTestReportsRecipeFilesItCannotStage(t *testing.T) {
	requireNonRootHere(t)
	testTestbed(t)
	p := writeTestRecipe(t, okRecipe)
	// Traversable but not listable: os.ReadFile of a known name still works,
	// os.ReadDir does not — so the recipe parses and the staging is what
	// fails, which is the arm under test.
	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
	if !strings.Contains(errOut.String(), "stage recipe files") {
		t.Errorf("want the step named: %q", errOut.String())
	}
}

// The entry that vanished between the listing and the stat. Only a seam can
// produce it, and leaving it unexercised would leave a return nobody checked.
func TestStageRecipeFilesReportsAnEntryThatVanished(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := dirEntryInfo
	dirEntryInfo = func(os.DirEntry) (os.FileInfo, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { dirEntryInfo = prev })

	if err := stageRecipeFiles(src, t.TempDir()); err == nil {
		t.Error("want the error surfaced, not swallowed")
	}
}

// The four answers have to stay four. A caller that cannot tell "it failed"
// from "it never ran" files bugs against packages for a network outage —
// which is what the first real sweep did, four times out of forty.
func TestTheFourOutcomesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for code, name := range map[int]string{
		0:             "pass",
		1:             "ran and failed",
		2:             "asked wrongly",
		exitNoTest:    "nothing to run",
		exitCannotRun: "could not run it",
	} {
		if prev, ok := seen[code]; ok {
			t.Errorf("%q and %q share exit %d", prev, name, code)
		}
		seen[code] = name
	}
	if len(seen) != 5 {
		t.Errorf("want five distinct codes, got %d", len(seen))
	}
}

// needsCompiler reads the COMMAND position, so a compiler named in prose or
// in a string does not pull llvm.org into the sandbox.
func TestNeedsCompilerAsksTheParserNotTheText(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         bool
	}{
		{"cc in command position", "cc test.c -lz", true},
		{"c++ behind a pipe", "cat x | c++ -x c++ -", true},
		{"clang++", "clang++ -std=c++17 t.cpp", true},
		{"named in a comment", "# build it with gcc first\ngawk --version", false},
		{"named in a string", `echo "compiled with cc"`, false},
		{"no compiler at all", "gawk --version | grep 5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsCompiler(tc.script); got != tc.want {
				t.Errorf("needsCompiler(%q) = %v, want %v", tc.script, got, tc.want)
			}
		})
	}
}

// End to end: the flag reaches the generated script.
func TestRunTestGivesACompilingTestACompiler(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	t.Setenv("ZBK_TARGET", "linux/x86-64")
	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\ntest: cc test.c\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	script, err := os.ReadFile(*got)
	if err != nil {
		t.Fatal(err)
	}
	// Host, not target, decides: WrapTest asks whether the MACHINE has one.
	if runtime.GOOS != "darwin" && !strings.Contains(string(script), "llvm.org") {
		t.Errorf("no compiler reached the script:\n%s", script)
	}
}

// An environment pkgx could not assemble is NOT-RUN, not FAIL.
func TestRunTestSeparatesAnUnassemblableEnvironmentFromAFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want string
	}{
		{"the env would not assemble", buildscript.EnvFailExit, "NOT-RUN"},
		{"the test ran and failed", 1, "FAIL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testTestbed(t)
			prev := testRun
			testRun = func(string, []string) error { return interp.ExitStatus(tc.code) }
			t.Cleanup(func() { testRun = prev })

			p := writeTestRecipe(t, okRecipe)
			var out, errOut bytes.Buffer
			code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut)
			wantCode := 1
			if tc.want == "NOT-RUN" {
				wantCode = exitCannotRun
			}
			if code != wantCode {
				t.Errorf("exit %d, want %d", code, wantCode)
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("want %q in: %q", tc.want, errOut.String())
			}
			// The reason, not the number: a caller records what comes back.
			if tc.want == "NOT-RUN" {
				if strings.Contains(errOut.String(), "exit status") {
					t.Errorf("reported a status nobody can look up: %q", errOut.String())
				}
				if !strings.Contains(errOut.String(), "could not be assembled") {
					t.Errorf("want the reason: %q", errOut.String())
				}
			}
		})
	}
}

// A test may name a dependency's prefix. Eleven recipes do, gnu.org/glibc
// among them.
func TestRunTestResolvesADependencysPrefixWhenTheScriptNamesOne(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	prev := resolveTestDep
	resolveTestDep = func(project, constraint string) (string, error) {
		if project != "gnu.org/gcc" {
			t.Errorf("asked about %q", project)
		}
		return "14.2.0", nil
	}
	t.Cleanup(func() { resolveTestDep = prev })

	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\n"+
		"test:\n  dependencies:\n    gnu.org/gcc: 14\n  script: cat {{deps.gnu.org/gcc.prefix}}/x\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	script, err := os.ReadFile(*got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(script), "{{deps.") {
		t.Errorf("a moustache reached the shell:\n%s", script)
	}
	if !strings.Contains(string(script), "gnu.org/gcc/v14.2.0/x") {
		t.Errorf("the prefix did not render:\n%s", script)
	}
}

// And a test that names none pays no round-trip: 1894 of the 1905 recipes
// with a test block would otherwise resolve dependencies for nothing, and a
// 503 would turn a passing test into one that never ran.
func TestRunTestResolvesNothingWhenTheScriptNamesNoDependency(t *testing.T) {
	testTestbed(t)
	stubRun(t, nil)
	prev := resolveTestDep
	resolveTestDep = func(string, string) (string, error) {
		t.Error("resolved a dependency the script never named")
		return "", errors.New("must not be called")
	}
	t.Cleanup(func() { resolveTestDep = prev })

	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\n"+
		"test:\n  dependencies:\n    gnu.org/gcc: 14\n  script: true\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
}

// A dependency that cannot be resolved is NOT-RUN, not a failure.
func TestRunTestReportsADependencyItCannotResolve(t *testing.T) {
	testTestbed(t)
	prev := resolveTestDep
	resolveTestDep = func(string, string) (string, error) { return "", errors.New("503") }
	t.Cleanup(func() { resolveTestDep = prev })

	p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\n"+
		"test:\n  dependencies:\n    gnu.org/gcc: 14\n  script: cat {{deps.gnu.org/gcc.prefix}}/x\n")
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
		t.Errorf("want %d, got %d", exitCannotRun, code)
	}
	if !strings.Contains(errOut.String(), "resolve test deps") {
		t.Errorf("want the step named: %q", errOut.String())
	}
}

// Privilege where the measured need is: a TEST gets GITHUB_TOKEN, a build
// does not.
//
// Two recipes of 1899 ask for it — github.com/spencerkimball/stargazers and
// github.com/mono0926/LicensePlist — and both ask in their `test:` block.
// No `build:` block in the pantry references it, our overlay has none, and
// bk's own fetcher never sends it, so SanitizedEnv stopped passing it to
// third-party build scripts running as root with a token that carries
// `packages: write` on the organisation.
func TestTheTestSandboxGetsTheTokenAndOnlyWhenThereIsOne(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		want  bool
	}{
		{"a token is set", "ghp_example", true},
		{"no token at all", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testTestbed(t)
			t.Setenv("GITHUB_TOKEN", tc.token)

			var env []string
			prev := testRun
			testRun = func(_ string, e []string) error { env = e; return nil }
			t.Cleanup(func() { testRun = prev })

			p := writeTestRecipe(t, okRecipe)
			var out, errOut bytes.Buffer
			if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
				t.Fatalf("runTest = %d (%s)", code, errOut.String())
			}
			got := slices.Contains(env, "GITHUB_TOKEN="+tc.token)
			if got != tc.want {
				t.Errorf("GITHUB_TOKEN in the test env = %v; want %v (env had %d entries)", got, tc.want, len(env))
			}
			// An empty token must not be forwarded as an empty variable: a
			// recipe testing `-z "$GITHUB_TOKEN"` would then see it set.
			if tc.token == "" {
				for _, e := range env {
					if strings.HasPrefix(e, "GITHUB_TOKEN=") {
						t.Errorf("an empty token was forwarded as %q", e)
					}
				}
			}
		})
	}
}

// The shims are real symlinks beside the sandbox, not a path in a string.
// `bk tools --scope test --all` counts 194 pantry tests that call `cc` by
// name; what they find on PATH is the whole fix.
func TestRunTestMaterialisesTheCompilerShims(t *testing.T) {
	testTestbed(t)
	got := stubRun(t, nil)
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("want 0, got %d (%s)", code, errOut.String())
	}
	// Beside the sandbox, never inside it: the next run empties the sandbox.
	shimDir := strings.TrimSuffix(*got, ".test.sh") + ".shims"
	for _, name := range []string{"cc", "gcc", "c++", "g++"} {
		fi, err := os.Lstat(filepath.Join(shimDir, name))
		if err != nil {
			t.Errorf("%s is not in the shim dir: %v", name, err)
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s is not a symlink to bk", name)
		}
	}
	// clang IS shimmed since #305. It was excluded while the shim looked
	// its driver up on PATH — $BK_CC's driver is clang and the shim dir is
	// first, so the shim found itself — and it is included now that the
	// shim skips its own directory. 77 recipes name a compiler in `env:`
	// and lost the sysroot for want of it.
	if _, err := os.Lstat(filepath.Join(shimDir, "clang")); err != nil {
		t.Errorf("clang is not shimmed, so a recipe naming it still loses the sysroot: %v", err)
	}
}

// A filesystem that refuses the symlinks must not take the other 1700 tests
// down with it: the run says so and goes on without them.
func TestRunTestSurvivesShimsItCannotMake(t *testing.T) {
	testTestbed(t)
	stubRun(t, nil)
	prev := writeShims
	writeShims = func(string, bool, string, string, string) error { return os.ErrPermission }
	t.Cleanup(func() { writeShims = prev })
	p := writeTestRecipe(t, okRecipe)
	var out, errOut bytes.Buffer
	if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
		t.Fatalf("a test was failed by its shims: %d (%s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "warning: compiler shims:") {
		t.Errorf("it did not say the shims are missing: %q", errOut.String())
	}
}

// ⛔⛔ `zbk test` ASKS THE STORE WHICH BUILD IT IS TESTING, and the three
// answers it can get are all held here. The old code composed
// `<store>/<project>/v<version>` and handed it to the script as `{{prefix}}`,
// which is now a path that never exists: a test would have run against an
// absent directory and reported whatever the script makes of that.
func TestRunTestNamesTheBuildItRunsAgainst(t *testing.T) {
	t.Run("nothing installed is NOT-RUN, and says so", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("ZPKG_PANTRY_DIR", dir)
		t.Setenv("ZPKG_DIR", filepath.Join(dir, "pkgx"))
		stubRun(t, nil)

		p := writeTestRecipe(t, okRecipe)
		var out, errOut bytes.Buffer
		if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
			t.Errorf("exit %d, want %d (%s)", code, exitCannotRun, errOut.String())
		}
		// The message has to name the project AND the version: "not installed"
		// alone sends the reader to look at the wrong one of the two.
		for _, want := range []string{"proj.org", "1.2.3"} {
			if !strings.Contains(errOut.String(), want) {
				t.Errorf("want %q in: %q", want, errOut.String())
			}
		}
	})

	t.Run("one installed renders its hashed prefix", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("ZPKG_PANTRY_DIR", dir)
		t.Setenv("ZPKG_DIR", filepath.Join(dir, "pkgx"))
		hash := installTestBuild(t, filepath.Join(dir, "pkgx"), "proj.org", "1.2.3")
		got := stubRun(t, nil)

		p := writeTestRecipe(t, "versions:\n  - 1.2.3\nbuild: make\ntest: ls {{prefix}}\n")
		var out, errOut bytes.Buffer
		if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != 0 {
			t.Fatalf("want 0, got %d (%s)", code, errOut.String())
		}
		script, err := os.ReadFile(*got)
		if err != nil {
			t.Fatal(err)
		}
		// ⛔ THE HASH THE STORE HOLDS, not one the test chose: installTestBuild
		// returns what it wrote, and the assertion is that the SAME string
		// reached the script.
		if !strings.Contains(string(script), "v1.2.3-h"+hash) {
			t.Errorf("the script does not name the installed build (-h%s):\n%s", hash, script)
		}
	})

	t.Run("two installed is AMBIGUOUS, not the newest", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("ZPKG_PANTRY_DIR", dir)
		t.Setenv("ZPKG_DIR", filepath.Join(dir, "pkgx"))
		store := filepath.Join(dir, "pkgx")
		v := bottle.Ver{Raw: "1.2.3"}
		for _, seed := range []string{"a", "b"} {
			h := bottle.StoreHash(v, "digest:"+seed, "")
			if err := os.MkdirAll(bottle.StoreBuildPrefix(store, "proj.org", v, h), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		prev := testRun
		t.Cleanup(func() { testRun = prev })
		testRun = func(string, []string) error {
			t.Error("a test ran against a build nobody chose")
			return nil
		}

		p := writeTestRecipe(t, okRecipe)
		var out, errOut bytes.Buffer
		if code := runTest([]string{"--recipe", p, "proj.org"}, &out, &errOut); code != exitCannotRun {
			t.Errorf("exit %d, want %d (%s)", code, exitCannotRun, errOut.String())
		}
	})
}
