//go:build darwin

package fixup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Majoring the directory of a dependency reference buys nothing if the
// FILENAME still names one patch release. This builds the shape that broke
// cairo — a dependency installed as libz.1.3.1.dylib with libz.1.dylib beside
// it — fixes the consumer up, then performs the upgrade the majored directory
// exists FOR: zlib 1.3.1 gives way to 1.3.2, v1 follows it, and the old
// full-version filename is gone.
//
// The control is the same tree with only the directory majored, which is what
// bk wrote before this change; it must fail the upgrade, or the test below
// proves nothing.
func TestAPatchUpgradeOfADependencyDoesNotOrphanItsDependents(t *testing.T) {
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
	zc := write("z.c", "int zed(void){ return 42; }\n")
	mainC := write("main.c", "#include <stdio.h>\nint zed(void);\nint main(void){ printf(\"zed=%d\\n\", zed()); return 0; }\n")

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	// A copy, never the original: macOS caches a code signature per vnode at
	// the first exec.
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

	// build lays out $ZPKG_DIR/<name> with zlib.example v1.3.1 — the real file
	// carrying the full version, the soname link beside it, and v1 pointing at
	// the version directory, exactly as pkgx installs one — plus a program
	// linked against the full-version file, as a build does when that is the
	// library's install name.
	build := func(name string) (zpkgDir, libPrefix, exePrefix, exe string) {
		t.Helper()
		zpkgDir = filepath.Join(root, name)
		libPrefix = filepath.Join(zpkgDir, "zlib.example", "v1.3.1")
		exePrefix = filepath.Join(zpkgDir, "other.org", "bar", "v2.0.0")
		if err := os.MkdirAll(filepath.Join(libPrefix, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(exePrefix, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		dylib := filepath.Join(libPrefix, "lib", "libz.1.3.1.dylib")
		exe = filepath.Join(exePrefix, "bin", "bar")
		run(cc, "-dynamiclib", "-install_name", dylib, "-Wl,-rpath,@loader_path/../../..", "-o", dylib, zc)
		if err := os.Symlink("libz.1.3.1.dylib", filepath.Join(libPrefix, "lib", "libz.1.dylib")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("v1.3.1", filepath.Join(zpkgDir, "zlib.example", "v1")); err != nil {
			t.Fatal(err)
		}
		run(cc, "-o", exe, mainC, dylib, "-Wl,-rpath,@loader_path/../../../..")
		return zpkgDir, libPrefix, exePrefix, exe
	}

	// upgrade is the event the major link is for: 1.3.2 replaces 1.3.1, ships
	// its own full-version file and soname link, and v1 follows.
	upgrade := func(zpkgDir string) {
		t.Helper()
		proj := filepath.Join(zpkgDir, "zlib.example")
		newLib := filepath.Join(proj, "v1.3.2", "lib")
		if err := os.MkdirAll(newLib, 0o755); err != nil {
			t.Fatal(err)
		}
		run(cc, "-dynamiclib", "-install_name", "@rpath/zlib.example/v1/lib/libz.1.dylib",
			"-Wl,-rpath,@loader_path/../../..", "-o", filepath.Join(newLib, "libz.1.3.2.dylib"), zc)
		if err := os.Symlink("libz.1.3.2.dylib", filepath.Join(newLib, "libz.1.dylib")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(proj, "v1.3.1")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(proj, "v1")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("v1.3.2", filepath.Join(proj, "v1")); err != nil {
			t.Fatal(err)
		}
	}

	// The control: the reference majored in the directory only, which is what
	// the previous code produced. Written by hand so the control does not
	// depend on the code under test to be wrong.
	{
		zpkgDir, _, _, exe := build("control")
		if got, err := runsFrom(exe); err != nil || got != "zed=42" {
			t.Fatalf("the control did not run in place: %q %v", got, err)
		}
		old := filepath.Join(zpkgDir, "zlib.example", "v1.3.1", "lib", "libz.1.3.1.dylib")
		run("install_name_tool", "-change", old, "@rpath/zlib.example/v1/lib/libz.1.3.1.dylib", exe)
		run("codesign", "-f", "-s", "-", exe)
		upgrade(zpkgDir)
		if got, err := runsFrom(exe); err == nil {
			t.Fatalf("a patch-level filename survived the upgrade (%q): this machine cannot tell the two forms apart, so the test below would prove nothing", got)
		}
	}

	zpkgDir, libPrefix, exePrefix, exe := build("pkgx")
	for _, prefix := range []string{libPrefix, exePrefix} {
		if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgDir}); err != nil {
			t.Fatalf("fixup %s: %v", prefix, err)
		}
	}

	strs, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := "@rpath/zlib.example/v1/lib/libz.1.dylib"
	found := false
	for _, s := range strs {
		if s == want {
			found = true
		}
		if strings.Contains(s, "libz.1.3.1.dylib") {
			t.Errorf("the patch-level filename survived the rewrite: %q", s)
		}
	}
	if !found {
		t.Fatalf("reference not reduced to the soname: %q", strs)
	}

	// And the outcome the control could not reach.
	upgrade(zpkgDir)
	got, err := runsFrom(exe)
	if err != nil {
		t.Fatalf("the fixed-up program did not survive its dependency's patch upgrade: %v\noutput: %q", err, got)
	}
	if got != "zed=42" {
		t.Errorf("output = %q, want zed=42", got)
	}
}
