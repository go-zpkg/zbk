package buildscript

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteLibexecHappy proves WriteLibexec creates the dir and materialises
// every shim as a symlink pointing at the running executable (bk itself), so
// exec'ing the shim re-enters bk's multi-call dispatch — not a shell script.
func TestWriteLibexecHappy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "libexec")
	if err := WriteLibexec(dir); err != nil {
		t.Fatalf("WriteLibexec: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	shim := filepath.Join(dir, "fix-shebangs.ts")

	// it is a symlink (not a regular file / embedded script)…
	fi, err := os.Lstat(shim)
	if err != nil {
		t.Fatalf("lstat shim: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("shim is not a symlink: %v", fi.Mode())
	}
	// …and it points at the running bk binary.
	target, err := os.Readlink(shim)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != self {
		t.Errorf("shim → %q, want %q", target, self)
	}
	// every declared shim name must be materialised.
	for name := range shims {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("shim %q missing: %v", name, err)
		}
	}
	// every brewkit helper bk satisfies must be present: fix-shebangs.ts
	// (relocatable shebangs), zpkvenv (new python-venv stage/seal) and the old
	// python-venv.{sh,py}/stubber family. A regression dropping any would break a
	// whole class of recipes.
	for _, want := range []string{"fix-shebangs.ts", "zpkvenv", "python-venv.sh", "python-venv.py", "python-venv-stubber.sh"} {
		if _, ok := shims[want]; !ok {
			t.Errorf("shim set missing %q", want)
		}
	}
}

func TestWriteLibexecErrors(t *testing.T) {
	restore := func() {
		mkdirAll, osExecutable, osSymlink = os.MkdirAll, os.Executable, os.Symlink
	}

	t.Run("mkdir", func(t *testing.T) {
		defer restore()
		mkdirAll = func(string, os.FileMode) error { return errBoomLibexec }
		if err := WriteLibexec("x"); !errors.Is(err, errBoomLibexec) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("executable", func(t *testing.T) {
		defer restore()
		osExecutable = func() (string, error) { return "", errBoomLibexec }
		if err := WriteLibexec(t.TempDir()); !errors.Is(err, errBoomLibexec) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		defer restore()
		osSymlink = func(string, string) error { return errBoomLibexec }
		if err := WriteLibexec(t.TempDir()); !errors.Is(err, errBoomLibexec) {
			t.Errorf("err = %v", err)
		}
	})
}

var errBoomLibexec = errors.New("boom")

// TestWriteLibexecForCompilerShims: in pkgx-libc mode the libexec dir also gets
// cc/gcc/c++/g++, because a recipe may call the compiler by NAME instead of
// through $CC (sqlite's autosetup tries `cc` then `gcc`) and would otherwise
// get a driver with none of the sovereign flags.
func TestWriteLibexecForCompilerShims(t *testing.T) {
	off := t.TempDir()
	if err := WriteLibexecFor(off, false, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err != nil {
		t.Fatal(err)
	}
	// Outside pkgx-libc mode the shims still exist: they carry
	// -ffile-prefix-map, which no recipe env may drop (go-zpkg/bk#387).
	if _, err := os.Lstat(filepath.Join(off, "cc")); err != nil {
		t.Fatalf("cc shim must exist in every mode: %v", err)
	}
	on := t.TempDir()
	if err := WriteLibexecFor(on, true, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err != nil {
		t.Fatal(err)
	}
	for _, n := range append([]string{"fix-shebangs.ts"}, compilerShims...) {
		fi, err := os.Lstat(filepath.Join(on, n))
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s: %v (want a symlink to bk)", n, err)
		}
	}
	// idempotent
	if err := WriteLibexecFor(on, true, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err != nil {
		t.Fatal(err)
	}
	// error branches: the base writer's, then the compiler-shim ones
	oldExec, oldLink := osExecutable, osSymlink
	defer func() { osExecutable, osSymlink = oldExec, oldLink }()
	osExecutable = func() (string, error) { return "", errors.New("boom") }
	if err := WriteLibexecFor(t.TempDir(), true, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err == nil {
		t.Fatal("want the executable-path error")
	}
	// and the SECOND lookup (the one the compiler shims do) failing on its own
	n := 0
	osExecutable = func() (string, error) {
		n++
		if n == 1 {
			return oldExec()
		}
		return "", errors.New("boom")
	}
	if err := WriteLibexecFor(t.TempDir(), true, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err == nil {
		t.Fatal("want the compiler-shim executable-path error")
	}
	osExecutable = oldExec
	calls := 0
	osSymlink = func(a, b string) error {
		calls++
		if calls > len(shims) {
			return errors.New("boom")
		}
		return oldLink(a, b)
	}
	if err := WriteLibexecFor(t.TempDir(), true, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err == nil {
		t.Fatal("want the compiler-shim symlink error")
	}
}

// The triple-prefixed spellings must be materialised too. autoconf looks for
// `x86_64-pc-linux-gnu-gcc` BEFORE the bare `gcc`, and when it finds the
// artifact's bare compiler instead of our shim it gets a driver with none of the
// sovereign sysroot/crt/runtime flags — libisl's configure then reports
// "C compiler cannot create executables".
func TestCompilerShimsCoverTriplePrefixedNames(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLibexecFor(dir, true, "x86_64-unknown-linux-gnu", "linux", "x86-64"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cc", "gcc", "c++", "g++",
		// bk's own notion of the triple…
		"x86_64-unknown-linux-gnu-gcc", "x86_64-unknown-linux-gnu-g++",
		// …and config.guess's, which is the one the failing build asked for.
		"x86_64-pc-linux-gnu-gcc", "x86_64-pc-linux-gnu-c++",
	} {
		if _, err := os.Lstat(filepath.Join(dir, want)); err != nil {
			t.Errorf("no shim for %s: %v", want, err)
		}
	}
}

// Both spellings are made deliberately: ours and config.guess's differ on
// x86_64 (`unknown` vs `pc`), and shimming only the name we happen to call
// ourselves would shim a name nobody looks up.
func TestCompilerShimsForBothSpellings(t *testing.T) {
	got := compilerShimsFor("x86_64-unknown-linux-gnu", "linux", "x86-64")
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n] {
			t.Errorf("duplicate shim %q", n)
		}
		seen[n] = true
	}
	for _, want := range []string{"x86_64-pc-linux-gnu-gcc", "x86_64-unknown-linux-gnu-gcc"} {
		if !seen[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	// aarch64: config.guess agrees with us, so there is exactly one spelling
	// and no duplicate.
	arm := compilerShimsFor("aarch64-unknown-linux-gnu", "linux", "aarch64")
	n := 0
	for _, s := range arm {
		if s == "aarch64-unknown-linux-gnu-gcc" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("aarch64-unknown-linux-gnu-gcc appears %d times in %v", n, arm)
	}
	// A platform with no config.guess spelling of its own contributes none.
	if len(compilerShimsFor("", "darwin", "aarch64")) != len(compilerShims) {
		t.Errorf("darwin must add no prefixed shims: %v", compilerShimsFor("", "darwin", "aarch64"))
	}
}

// A linux architecture config.guess has no spelling for adds no prefixed shim,
// and must not fall through to some other arch's triple.
func TestConfigGuessTripleUnknownArch(t *testing.T) {
	if got := configGuessTriple("linux", "riscv64"); got != "" {
		t.Errorf("configGuessTriple(linux, riscv64) = %q, want empty", got)
	}
	if n := len(compilerShimsFor("riscv64-unknown-linux-gnu", "linux", "riscv64")); n != len(compilerShims)+len(compilerShims) {
		t.Errorf("want the bare shims plus one triple's worth, got %d", n)
	}
}

// The libtool shim is materialised on darwin and nowhere else: the name
// collision is a macOS fact, and putting a `libtool` ahead of PATH on linux
// would shadow the GNU one every autotools build there expects.
func TestWriteLibexecForPutsLibtoolOnDarwinOnly(t *testing.T) {
	for _, tc := range []struct {
		platform string
		want     bool
	}{
		{"darwin", true},
		{"linux", false},
	} {
		dir := t.TempDir()
		if err := WriteLibexecFor(dir, false, "x86_64-apple-darwin", tc.platform, "x86-64"); err != nil {
			t.Fatal(err)
		}
		_, err := os.Lstat(filepath.Join(dir, "libtool"))
		if got := err == nil; got != tc.want {
			t.Errorf("%s: libtool shim present = %v, want %v", tc.platform, got, tc.want)
		}
	}
}

// A symlink that cannot be made must stop the build rather than leave the
// wrong libtool first on PATH.
//
// There is deliberately no companion test for "os.Executable failed": the
// call above this one already returns that error, so the branch is
// unreachable. A test asserting it would have passed on the EARLIER return —
// which is how it was written first, and why the coverage gate still showed
// the block at zero.
func TestWriteLibexecForLibtoolErrors(t *testing.T) {
	t.Run("the symlink cannot be made", func(t *testing.T) {
		oldSym := osSymlink
		n := 0
		osSymlink = func(a, b string) error {
			n++
			if filepath.Base(b) == "libtool" {
				return errBoomLibexec
			}
			return oldSym(a, b)
		}
		defer func() { osSymlink = oldSym }()
		if err := WriteLibexecFor(t.TempDir(), false, "t", "darwin", "x86-64"); !errors.Is(err, errBoomLibexec) {
			t.Errorf("err = %v, want the injected one", err)
		}
	})
}

// s390x's config.guess answer is measured, not patterned. The two entries
// beside it disagree about the vendor field -- x86_64-PC-linux-gnu against
// aarch64-UNKNOWN-linux-gnu -- so there was no rule to extend, and upstream
// config.guess run on the LinuxONE machine gives a third: ibm.
func TestConfigGuessTripleS390x(t *testing.T) {
	if got := configGuessTriple("linux", "s390x"); got != "s390x-ibm-linux-gnu" {
		t.Errorf("configGuessTriple(linux, s390x) = %q, want s390x-ibm-linux-gnu", got)
	}
	// And it must reach the shims, which is the only reason the triple exists:
	// autoconf looks up <triple>-gcc before gcc.
	names := compilerShimsFor("s390x-unknown-linux-gnu", "linux", "s390x")
	var found bool
	for _, n := range names {
		if n == "s390x-ibm-linux-gnu-gcc" {
			found = true
		}
	}
	if !found {
		t.Errorf("no s390x-ibm-linux-gnu-gcc shim among %v", names)
	}
}
