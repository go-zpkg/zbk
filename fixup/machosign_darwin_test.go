//go:build darwin

package fixup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The crafted Mach-Os elsewhere in this package prove the arithmetic against
// itself. This one hands the result to the system: macOS decides whether the
// signature is valid, and the kernel decides whether the binary runs. Both
// judgements are ones bk cannot fake.
//
// It is the test that would have caught the defect in the first place. A
// artifact with a rewritten install name and a stale signature is not slow or
// subtly wrong — it is killed on sight, with no output whatsoever:
//
//	$ ./bin/main ; echo $?
//	137
//
// so nothing short of running the thing reveals it.
func TestRewrittenBinaryStillRunsAndVerifies(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no cc: nothing to build a real Mach-O with")
	}
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		t.Skip("no codesign: the judge is missing")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "lib")
	staged := real + "+brewing" // what the install name is baked with
	for _, d := range []string{real, staged, filepath.Join(dir, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	foo := write("foo.c", "int foo(void){ return 42; }\n")
	mainC := write("main.c", "#include <stdio.h>\nint foo(void);\nint main(void){ printf(\"foo=%d\\n\", foo()); return 0; }\n")

	dylib := filepath.Join(staged, "libfoo.dylib")
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run(cc, "-dynamiclib", "-install_name", dylib, "-o", dylib, foo)
	exe := filepath.Join(dir, "bin", "main")
	run(cc, "-o", exe, mainC, dylib)

	// The staged tree is gone by the time an artifact is installed; only the final
	// one exists. Until the install name is fixed, the binary cannot resolve it.
	if err := os.Rename(dylib, filepath.Join(real, "libfoo.dylib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}

	// Show the binary is broken BEFORE the rewrite — on a copy, never on the
	// file about to be rewritten. macOS caches a code signature per vnode at
	// the first exec: run the original here and the kernel would then validate
	// the rewritten pages against the cdhash it cached, and SIGKILL it however
	// correct the new signature is. Measured on a byte-identical pair: same
	// inode, exit 137; fresh inode, runs. `codesign -v` passes on both, so the
	// tool cannot see it either — a test that skipped the copy would fail for a
	// reason that has nothing to do with what it is testing.
	broken := filepath.Join(dir, "bin", "before")
	if err := copyFile(exe, broken); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(broken).CombinedOutput(); err == nil {
		t.Fatalf("the binary ran before its install name was fixed: %s", out)
	}

	for _, p := range []string{exe, filepath.Join(real, "libfoo.dylib")} {
		if err := RewriteMachoStrings(p, func(s string) string {
			return strings.ReplaceAll(s, "+brewing", "")
		}); err != nil {
			t.Fatalf("rewrite %s: %v", p, err)
		}
	}

	// macOS's own verdict on the signatures we recomputed.
	for _, p := range []string{exe, filepath.Join(real, "libfoo.dylib")} {
		if out, err := exec.Command(codesign, "-v", p).CombinedOutput(); err != nil {
			t.Errorf("codesign rejected what we re-signed in %s: %v\n%s", filepath.Base(p), err, out)
		}
	}
	// And the kernel's, which is the one that matters: an invalid signature is
	// SIGKILL with an empty stdout, indistinguishable from a program that
	// simply printed nothing.
	out, err := exec.Command(exe).CombinedOutput()
	if err != nil {
		t.Fatalf("the rewritten binary did not run: %v\noutput: %q", err, out)
	}
	if strings.TrimSpace(string(out)) != "foo=42" {
		t.Errorf("output = %q, want foo=42", out)
	}
}

// copyFile duplicates a file with its mode — a fresh inode, which is what the
// caller is really after.
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, fi.Mode().Perm())
}
