//go:build darwin

package fixup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The point of the whole change: two ABI lines of ONE project, and a consumer
// that keeps working when the other line takes v<major>.
//
// libxml2 is the real case — 2.13.9 ships libxml2.2.dylib, 2.15.4 ships
// libxml2.16.dylib, both claim v2, and open-mpi.org needs both at once. This
// reproduces the shape with a real linker.
func TestAConsumerBindsToItsABILineNotTheMajor(t *testing.T) {
	// Both ways round. WITHOUT the abi- link the consumer records v1 and dies
	// when the other line takes it — that is today's behaviour and the control
	// that makes the other result mean something.
	t.Run("with the link", func(t *testing.T) { abiLineScenario(t, true) })
	t.Run("without it, the control", func(t *testing.T) { abiLineScenario(t, false) })
}

func abiLineScenario(t *testing.T, withLink bool) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no cc")
	}
	root := t.TempDir()
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(n, body string) string {
		p := filepath.Join(src, n)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	foo := write("foo.c", "int foo(void){ return 42; }\n")
	mainC := write("main.c", "#include <stdio.h>\nint foo(void);\nint main(void){ printf(\"foo=%d\\n\", foo()); return 0; }\n")
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
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

	// line one: v1.0.0, soname libfoo.1.dylib, and the links a store writes.
	zpkgDir := filepath.Join(root, "store")
	libPrefix := filepath.Join(zpkgDir, "abi.example", "v1.0.0")
	exePrefix := filepath.Join(zpkgDir, "other.org", "bar", "v2.0.0")
	if err := os.MkdirAll(filepath.Join(libPrefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(exePrefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	dylib := filepath.Join(libPrefix, "lib", "libfoo.1.dylib")
	run(cc, "-dynamiclib", "-install_name", dylib, "-Wl,-rpath,@loader_path/../../..", "-o", dylib, foo)
	proj := filepath.Join(zpkgDir, "abi.example")
	links := []string{"v1"}
	if withLink {
		links = append(links, "abi-libfoo.1.dylib")
	}
	for _, l := range links {
		if err := os.Symlink("v1.0.0", filepath.Join(proj, l)); err != nil {
			t.Fatal(err)
		}
	}

	exe := filepath.Join(exePrefix, "bin", "bar")
	run(cc, "-o", exe, mainC, dylib, "-Wl,-rpath,@loader_path/../../../..")
	for _, p := range []string{libPrefix, exePrefix} {
		if err := FixUp(Options{Prefix: p, Platform: "darwin", ZpkgDir: zpkgDir}); err != nil {
			t.Fatalf("fixup %s: %v", p, err)
		}
	}

	strs, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := "@rpath/abi.example/abi-libfoo.1.dylib/lib/libfoo.1.dylib"
	if !withLink {
		want = "@rpath/abi.example/v1/lib/libfoo.1.dylib"
	}
	found := false
	for _, s := range strs {
		if s == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("reference is not %q: %q", want, strs)
	}
	if got, err := runsFrom(exe); err != nil || got != "foo=42" {
		t.Fatalf("it did not run in place: %q %v", got, err)
	}

	// The other line arrives and takes v1 — which is what a minor upgrade does.
	other := filepath.Join(zpkgDir, "abi.example", "v1.5.0")
	if err := os.MkdirAll(filepath.Join(other, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	run(cc, "-dynamiclib", "-install_name", "@rpath/abi.example/abi-libfoo.2.dylib/lib/libfoo.2.dylib",
		"-Wl,-rpath,@loader_path/../../..", "-o", filepath.Join(other, "lib", "libfoo.2.dylib"), foo)
	if err := os.Remove(filepath.Join(proj, "v1")); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"v1", "abi-libfoo.2.dylib"} {
		if err := os.Symlink("v1.5.0", filepath.Join(proj, l)); err != nil {
			t.Fatal(err)
		}
	}

	got, rerr := runsFrom(exe)
	if withLink {
		if rerr != nil || got != "foo=42" {
			t.Fatalf("the consumer lost its library when the other line took v1: %q %v", got, rerr)
		}
		return
	}
	if rerr == nil {
		t.Fatalf("the control survived the other line taking v1 (%q), so this machine cannot tell the two forms apart", got)
	}
}
