package fixup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireNonRoot skips permission-based error tests when running as root, where
// the kernel ignores the mode bits we rely on to force failures.
func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-based error injection is a no-op for root")
	}
}

func TestFixPCFilesReadErrors(t *testing.T) {
	requireNonRoot(t)
	// unreadable .pc file → rewriteFile ReadFile error → propagates through FixUp
	prefix := t.TempDir()
	pc := filepath.Join(prefix, "lib", "pkgconfig", "x.pc")
	write(t, pc, "prefix="+prefix)
	os.Chmod(pc, 0)
	defer os.Chmod(pc, 0o644)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected error from unreadable .pc")
	}

	// unreadable pkgconfig dir → ReadDir error
	prefix2 := t.TempDir()
	d := filepath.Join(prefix2, "lib", "pkgconfig")
	write(t, filepath.Join(d, "y.pc"), "prefix="+prefix2)
	os.Chmod(d, 0)
	defer os.Chmod(d, 0o755)
	if err := FixUp(Options{Prefix: prefix2, Platform: "linux"}); err == nil {
		t.Error("expected error from unreadable pkgconfig dir")
	}
}

// A read-only .cmake is rewritten too, and keeps its mode. Relocation is an
// in-place rewrite everywhere in this package, and a package may install any of
// its files read-only.
func TestRewriteFileOnAReadOnlyFile(t *testing.T) {
	requireNonRoot(t)
	prefix := t.TempDir()
	cm := filepath.Join(prefix, "lib", "cmake", "F.cmake")
	write(t, cm, "set(X \""+prefix+"\")")
	if err := os.Chmod(cm, 0o444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cm, 0o644)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err != nil {
		t.Fatalf("a read-only .cmake was refused: %v", err)
	}
	b, err := os.ReadFile(cm)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), prefix) {
		t.Errorf("the absolute prefix survived: %s", b)
	}
	fi, err := os.Stat(cm)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o444 {
		t.Errorf("mode = %o, want 444 restored", fi.Mode().Perm())
	}
}

func TestRemoveLaDirError(t *testing.T) {
	requireNonRoot(t)
	prefix := t.TempDir()
	lib := filepath.Join(prefix, "lib")
	write(t, filepath.Join(lib, "z.la"), "x")
	os.Chmod(lib, 0o500) // no write on dir → Remove fails
	defer os.Chmod(lib, 0o755)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected Remove error in read-only lib")
	}
}

func TestConsolidateLib64MkdirError(t *testing.T) {
	prefix := t.TempDir()
	// lib exists as a regular FILE → MkdirAll(lib) must fail
	write(t, filepath.Join(prefix, "lib"), "iam a file")
	write(t, filepath.Join(prefix, "lib64", "x.so"), "x")
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected MkdirAll error when lib is a file")
	}
}

func TestFlattenHeadersReadError(t *testing.T) {
	requireNonRoot(t)
	prefix := t.TempDir()
	sub := filepath.Join(prefix, "include", "only")
	write(t, filepath.Join(sub, "a.h"), "h")
	os.Chmod(sub, 0) // unreadable subdir → ReadDir(subdir) error
	defer os.Chmod(sub, 0o755)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected ReadDir error on unreadable include subdir")
	}
}

func TestFlattenHeadersRenameError(t *testing.T) {
	requireNonRoot(t)
	prefix := t.TempDir()
	inc := filepath.Join(prefix, "include")
	sub := filepath.Join(inc, "only")
	write(t, filepath.Join(sub, "a.h"), "h")
	os.Chmod(inc, 0o500) // can't create entries in include → Rename up fails
	defer os.Chmod(inc, 0o755)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected Rename error into read-only include")
	}
}

// A package is entitled to install its files read-only — autotools does it
// routinely — and relocation is an in-place rewrite, so the mode has to be
// lifted for the write and put back afterwards. tcl-lang.org ships every
// library as -r-xr-xr-x, and the build died at the last step with
//
//	fix-up: open …/lib/libtcl8.6.dylib: permission denied
//
// having compiled and installed perfectly.
func TestSetRunpathOnAReadOnlyFile(t *testing.T) {
	requireNonRoot(t)
	p := buildELF64LE(t, "/opt/placeholder/aaaaaaaaaaaaaaaaaaaa", "libc.so.6", 40)
	if err := os.Chmod(p, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o644)
	if err := SetRunpath(p, "$ORIGIN/x"); err != nil {
		t.Fatalf("a read-only ELF was refused: %v", err)
	}
	got, err := ReadRunpath(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "$ORIGIN/x" {
		t.Errorf("RUNPATH = %q, want it rewritten", got)
	}
	// The bottle must ship the permissions the package chose, not the ones we
	// needed for a moment.
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o555 {
		t.Errorf("mode = %o, want 555 restored", fi.Mode().Perm())
	}
}

// The write bit cannot always be lifted — a read-only mount, or a directory we
// may not chmod in. That must surface, not be swallowed.
func TestEnsureWritableChmodError(t *testing.T) {
	p := buildELF64LE(t, "/opt/placeholder/aaaaaaaaaaaaaaaaaaaa", "libc.so.6", 40)
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o644)
	saved := osChmod
	defer func() { osChmod = saved }()
	osChmod = func(string, os.FileMode) error { return errInject }
	if err := SetRunpath(p, "$ORIGIN/x"); !errors.Is(err, errInject) {
		t.Errorf("err = %v, want the chmod error", err)
	}
}

// And a file that is not there at all fails at the stat, before any of it.
func TestEnsureWritableStatError(t *testing.T) {
	if _, err := ensureWritable(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("want an error for a file that does not exist")
	}
	if _, err := modeOf(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("want an error from modeOf too")
	}
}

func TestFixCMakeWalkError(t *testing.T) {
	requireNonRoot(t)
	prefix := t.TempDir()
	sub := filepath.Join(prefix, "lib", "cmake", "sub")
	write(t, filepath.Join(sub, "F.cmake"), "x")
	os.Chmod(sub, 0) // WalkDir invokes the callback with a permission error
	defer os.Chmod(sub, 0o755)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected WalkDir error under lib/cmake")
	}
}

func TestWalkExesReadError(t *testing.T) {
	requireNonRoot(t)
	prefix := t.TempDir()
	bin := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(bin, 0) // WalkDir hits a permission error
	defer os.Chmod(bin, 0o755)
	if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); err == nil {
		t.Error("expected WalkDir error on unreadable bin")
	}
}

// The same chmod failure at the other two in-place writers: the Mach-O rewrite
// and the .pc/.cmake rewrite. A file we cannot make writable must stop the
// relocation, not be skipped silently — a half-relocated bottle is the one
// outcome nobody can check.
func TestEnsureWritableChmodErrorAtEveryWriter(t *testing.T) {
	t.Run("mach-o", func(t *testing.T) {
		p := buildMachO(t, machoCmd{lcIDDylib, "/opt/x/v1+brewing/lib/libz.dylib"})
		if err := os.Chmod(p, 0o400); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(p, 0o644)
		saved := osChmod
		defer func() { osChmod = saved }()
		osChmod = func(string, os.FileMode) error { return errInject }
		err := RewriteMachoStrings(p, func(s string) string {
			return strings.ReplaceAll(s, "+brewing", "")
		})
		if !errors.Is(err, errInject) {
			t.Errorf("err = %v, want the chmod error", err)
		}
	})
	t.Run("cmake", func(t *testing.T) {
		prefix := t.TempDir()
		cm := filepath.Join(prefix, "lib", "cmake", "F.cmake")
		write(t, cm, "set(X \""+prefix+"\")")
		if err := os.Chmod(cm, 0o400); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(cm, 0o644)
		saved := osChmod
		defer func() { osChmod = saved }()
		osChmod = func(string, os.FileMode) error { return errInject }
		if err := FixUp(Options{Prefix: prefix, Platform: "linux"}); !errors.Is(err, errInject) {
			t.Errorf("err = %v, want the chmod error", err)
		}
	})
}

// An @rpath reference that names nothing under $ZPKG_DIR is left exactly as it
// is: /usr/lib and the frameworks are not ours to rewrite.
func TestRpathReferenceOutsideZpkgDirIsUntouched(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, "@rpath/../outside/libfoo.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != "@rpath/../outside/libfoo.dylib" {
		t.Errorf("string = %q, want it untouched", got[1])
	}
}

// The dead-rpath check reads the file twice; both reads must surface their
// error rather than let a binary through unexamined.
func TestCheckRpathResolvableReadErrors(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe, machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})
	for _, nth := range []int{1, 2} {
		defer restoreReadFile(os.ReadFile)
		calls := 0
		osReadFile = func(p string) ([]byte, error) {
			calls++
			if calls == nth {
				return nil, errInject
			}
			return os.ReadFile(p)
		}
		if err := checkRpathResolvable(exe, Options{}); !errors.Is(err, errInject) {
			t.Errorf("read %d: err = %v, want the injected error", nth, err)
		}
		osReadFile = os.ReadFile
	}
}

// And the same on the branch that reaches it after a rewrite.
func TestRewriteMachoDeadRpathAfterRewrite(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe, machoCmd{lcIDDylib, prefix + "+brewing/lib/libthing.dylib"},
		machoCmd{lcLoadDylib, "@rpath/tukaani.org/xz/v5.8.3/lib/liblzma.5.dylib"})
	err := FixUp(Options{Prefix: prefix, BuildInstall: prefix + "+brewing", Platform: "darwin", ZpkgDir: pkgx})
	if !errors.Is(err, ErrDeadRpath) {
		t.Errorf("err = %v, want ErrDeadRpath after a rewrite too", err)
	}
}

// A write failure during the Mach-O rewrite must reach the caller — it is the
// difference between a bottle that was relocated and one that was not.
func TestRewriteMachoWriteErrorSurfaces(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe, machoCmd{lcIDDylib, prefix + "+brewing/lib/libthing.dylib"})
	saved := osWriteFile
	defer func() { osWriteFile = saved }()
	osWriteFile = func(string, []byte, os.FileMode) error { return errInject }
	err := FixUp(Options{Prefix: prefix, BuildInstall: prefix + "+brewing", Platform: "darwin", ZpkgDir: pkgx})
	if !errors.Is(err, errInject) {
		t.Errorf("err = %v, want the write error", err)
	}
}
