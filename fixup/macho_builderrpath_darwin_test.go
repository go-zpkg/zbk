//go:build darwin

package fixup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The arithmetic is proved against itself elsewhere; this hands the result to
// the system. Removing a load command changes the header and so invalidates the
// signature, and on Apple silicon that is SIGKILL with no output. macOS's
// codesign and the kernel are the judges.
func TestBinaryWithItsBuilderRpathRemovedStillVerifiesAndRuns(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no cc")
	}
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		t.Skip("no codesign")
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "builder-store") // stands in for the runner's ~/.pkgx
	src := filepath.Join(dir, "main.c")
	if err := os.WriteFile(src, []byte("#include <stdio.h>\nint main(void){puts(\"ok\");return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "bin", "main")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-o", exe, src, "-Wl,-rpath,"+store, "-Wl,-rpath,@loader_path/..").CombinedOutput(); err != nil {
		t.Fatalf("cc: %v\n%s", err, out)
	}
	has := func(p string) bool {
		for _, r := range rpathsOf(t, p) {
			if r == store {
				return true
			}
		}
		return false
	}
	// BEFORE, on a copy (a fresh inode: macOS caches the signature per vnode at
	// first exec, so running the original first would poison the after-run).
	before := filepath.Join(dir, "bin", "before")
	if err := copyFile(exe, before); err != nil {
		t.Fatal(err)
	}
	if !has(before) {
		t.Fatal("control failed: the real binary does not carry the builder rpath before the rewrite")
	}
	if out, err := exec.Command(before).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("control: the unmodified binary did not run: %v %q", err, out)
	}

	if err := rewriteMacho(exe, Options{Prefix: dir, Platform: "darwin", ZpkgDir: store}); err != nil {
		t.Fatal(err)
	}
	if has(exe) {
		t.Fatal("the builder rpath survived")
	}
	if out, err := exec.Command(codesign, "-v", exe).CombinedOutput(); err != nil {
		t.Fatalf("codesign rejected the re-signed binary: %v\n%s", err, out)
	}
	if err := checkMachoSignature(exe); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(exe).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("the rewritten binary did not run: %v %q", err, out)
	}
}
