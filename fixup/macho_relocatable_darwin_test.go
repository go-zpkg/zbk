//go:build darwin

package fixup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// What a darwin bottle is FOR: to work on a machine that is not the one that
// built it. Everything else here checks a step; this checks the outcome.
//
// It builds a two-package $ZPKG_DIR the way bk lays one out — a library in
// acme.org/foo/v1.2.3/lib, a program in other.org/bar/v2.0.0/bin — runs the
// real FixUp over both, then MOVES the whole tree and runs the program from
// its new home. A bottle whose dependency is named by absolute install name
// cannot survive that move, and until this change every darwin bottle was.
func TestBottleSurvivesBeingMoved(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no cc: nothing to build a real Mach-O with")
	}
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		p := filepath.Join(src, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	foo := write("foo.c", "int foo(void){ return 42; }\n")
	mainC := write("main.c", "#include <stdio.h>\nint foo(void);\nint main(void){ printf(\"foo=%d\\n\", foo()); return 0; }\n")

	// build lays out one $ZPKG_DIR and returns (zpkgDir, libPrefix, exePrefix,
	// exe). The rpaths are the ones bk's wrapper now links in: relative, at the
	// depth this layout implies.
	build := func(name string) (string, string, string, string) {
		t.Helper()
		zpkgDir := filepath.Join(root, name)
		libPrefix := filepath.Join(zpkgDir, "acme.org", "foo", "v1.2.3")
		exePrefix := filepath.Join(zpkgDir, "other.org", "bar", "v2.0.0")
		if err := os.MkdirAll(filepath.Join(libPrefix, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(exePrefix, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		dylib := filepath.Join(libPrefix, "lib", "libfoo.dylib")
		exe := filepath.Join(exePrefix, "bin", "bar")
		up := "@loader_path/../../../.."
		run := func(args ...string) {
			t.Helper()
			if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
			}
		}
		run(cc, "-dynamiclib", "-install_name", dylib, "-Wl,-rpath,"+up, "-o", dylib, foo)
		// pkgx links the major version beside the full one (v1 -> v1.2.3), and
		// the rewritten reference relies on it: a dependency's minor upgrade
		// must not orphan its dependents.
		if err := os.Symlink("v1.2.3", filepath.Join(filepath.Dir(libPrefix), "v1")); err != nil {
			t.Fatal(err)
		}
		run(cc, "-o", exe, mainC, dylib, "-Wl,-rpath,"+up)
		return zpkgDir, libPrefix, exePrefix, exe
	}

	// A copy, never the original: macOS caches a code signature per vnode at
	// the first exec, and a file rewritten after being run is killed however
	// correct its new signature is.
	runsFrom := func(exe string) (string, error) {
		t.Helper()
		cp := exe + ".copy"
		b, err := os.ReadFile(exe)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cp, b, 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(cp).CombinedOutput()
		os.Remove(cp)
		return strings.TrimSpace(string(out)), err
	}

	// The control: the same tree, moved WITHOUT being fixed up. If this one
	// still ran, the test below would prove nothing about the fix.
	{
		zpkgDir, _, exePrefix, exe := build("control")
		if got, err := runsFrom(exe); err != nil || got != "foo=42" {
			t.Fatalf("the control did not even run in place: %q %v", got, err)
		}
		moved := zpkgDir + "-moved"
		if err := os.Rename(zpkgDir, moved); err != nil {
			t.Fatal(err)
		}
		movedExe := filepath.Join(moved, exe[len(zpkgDir)+1:])
		_ = exePrefix
		if got, err := runsFrom(movedExe); err == nil {
			t.Fatalf("an unfixed bottle survived the move (%q): the absolute install name resolved, so this machine cannot tell the two apart", got)
		}
	}

	zpkgDir, libPrefix, exePrefix, exe := build("pkgx")
	for _, prefix := range []string{libPrefix, exePrefix} {
		if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgDir}); err != nil {
			t.Fatalf("fixup %s: %v", prefix, err)
		}
	}

	// The reference must now be relative to the rpath, version and all: pkgx
	// installs each version in its own directory, and a bottle may not assume a
	// major-version symlink exists at load time.
	strs, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := "@rpath/acme.org/foo/v1/lib/libfoo.dylib"
	found := false
	for _, s := range strs {
		if s == want {
			found = true
		}
		if strings.HasPrefix(s, zpkgDir) {
			t.Errorf("a path into the build machine's $ZPKG_DIR survived: %q", s)
		}
	}
	if !found {
		t.Fatalf("dependency not rewritten: %q", strs)
	}

	// And the outcome: the whole tree elsewhere, still working.
	moved := zpkgDir + "-moved"
	if err := os.Rename(zpkgDir, moved); err != nil {
		t.Fatal(err)
	}
	movedExe := filepath.Join(moved, exe[len(zpkgDir)+1:])
	got, err := runsFrom(movedExe)
	if err != nil {
		t.Fatalf("the fixed-up bottle did not run after being moved: %v\noutput: %q", err, got)
	}
	if got != "foo=42" {
		t.Errorf("output = %q, want foo=42", got)
	}
}

// A binary with no rpath reaching $ZPKG_DIR keeps its absolute install names.
// Rewriting them to @rpath/… would resolve to nothing at all, trading a bottle
// that works on one machine for a bottle that works on none.
func TestWithoutAnRpathTheNamesAreLeftAlone(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no cc")
	}
	root := t.TempDir()
	zpkgDir := filepath.Join(root, "pkgx")
	libPrefix := filepath.Join(zpkgDir, "acme.org", "foo", "v1.2.3")
	exePrefix := filepath.Join(zpkgDir, "other.org", "bar", "v2.0.0")
	for _, d := range []string{filepath.Join(libPrefix, "lib"), filepath.Join(exePrefix, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	foo := filepath.Join(root, "foo.c")
	mainC := filepath.Join(root, "main.c")
	if err := os.WriteFile(foo, []byte("int foo(void){ return 42; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainC, []byte("int foo(void);\nint main(void){ return foo() == 42 ? 0 : 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dylib := filepath.Join(libPrefix, "lib", "libfoo.dylib")
	exe := filepath.Join(exePrefix, "bin", "bar")
	for _, args := range [][]string{
		{cc, "-dynamiclib", "-install_name", dylib, "-o", dylib, foo},
		{cc, "-o", exe, mainC, dylib}, // no -rpath at all
	} {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	var logged []string
	if err := FixUp(Options{Prefix: exePrefix, Platform: "darwin", ZpkgDir: zpkgDir,
		Log: func(s string) { logged = append(logged, s) }}); err != nil {
		t.Fatal(err)
	}
	strs, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range strs {
		if strings.HasPrefix(s, "@rpath/") {
			t.Errorf("rewrote %q into an @rpath the binary cannot resolve", s)
		}
	}
	if !strings.Contains(strings.Join(logged, "\n"), "no rpath reaching") {
		t.Errorf("the refusal was silent; log was:\n%s", strings.Join(logged, "\n"))
	}
}
