package fixup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// place writes a crafted Mach-O at an arbitrary path — buildMachO picks its
// own, and where a binary SITS is half of what the rewrite decides.
func place(t *testing.T, path string, cmds ...machoCmd) {
	t.Helper()
	b, err := os.ReadFile(buildMachO(t, cmds...))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// An install name pointing into $ZPKG_DIR becomes an @rpath reference, so the
// artifact resolves it wherever $ZPKG_DIR turns out to be.
func TestInstallNamesBecomeRpathReferences(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "other.org", "bar", "v2.0.0")
	exe := filepath.Join(prefix, "bin", "bar")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, filepath.Join(zpkgx, "acme.org/foo/v1.2.3/lib/libfoo.dylib")},
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"@loader_path/../../../..",                // an rpath is a search root, not a reference
		"@rpath/acme.org/foo/v1/lib/libfoo.dylib", // major-versioned: v1 is a symlink pkgx maintains
		"/usr/lib/libSystem.B.dylib",              // the OS is not in $ZPKG_DIR
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("string %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The same file with an rpath that does NOT reach $ZPKG_DIR keeps its absolute
// names: @rpath would resolve to nothing, which is worse than a path that at
// least works on one machine.
func TestNoReachingRpathLeavesNamesAbsolute(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "other.org", "bar", "v2.0.0")
	exe := filepath.Join(prefix, "bin", "bar")
	dep := filepath.Join(zpkgx, "acme.org/foo/v1.2.3/lib/libfoo.dylib")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/.."}, // stops at the version dir
		machoCmd{lcLoadDylib, dep},
	)
	var logged []string
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx,
		Log: func(s string) { logged = append(logged, s) }}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != dep {
		t.Errorf("string = %q, want it left at %q", got[1], dep)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "no rpath reaching") {
		t.Errorf("the refusal was silent:\n%s", strings.Join(logged, "\n"))
	}
}

// Every shape an rpath can take, and whether it reaches $ZPKG_DIR from a
// binary installed at <pkgx>/other.org/bar/v2.0.0/bin/bar.
func TestRpathReaches(t *testing.T) {
	zpkgx := "/opt/.pkgx"
	exe := zpkgx + "/other.org/bar/v2.0.0/bin/bar"
	for _, tc := range []struct {
		name  string
		rpath string
		want  bool
	}{
		{"relative, right depth", "@loader_path/../../../..", true},
		{"relative, too shallow", "@loader_path/../..", false},
		{"the executable's own path", "@executable_path/../../../..", true},
		{"absolute, the same dir", zpkgx, true},
		{"absolute, another dir", "/usr/local/lib", false},
		{"neither absolute nor anchored", "lib", false},
		{"@rpath itself, which anchors nothing", "@rpath/lib", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rpathReaches(exe, zpkgx, []string{tc.rpath}); got != tc.want {
				t.Errorf("rpathReaches(%q) = %v, want %v", tc.rpath, got, tc.want)
			}
		})
	}
	if rpathReaches(exe, zpkgx, nil) {
		t.Error("no rpath at all reached somewhere")
	}
}

// underDir must not accept a sibling that merely starts with the same letters:
// /opt/.pkgxdirty is not inside /opt/.pkgx.
func TestUnderDir(t *testing.T) {
	for _, tc := range []struct {
		p, dir, rest string
		ok           bool
	}{
		{"/opt/.pkgx/acme.org/x", "/opt/.pkgx", "acme.org/x", true},
		{"/opt/.pkgxdirty/acme.org/x", "/opt/.pkgx", "", false},
		{"/opt/.pkgx", "/opt/.pkgx", "", false},
		{"/opt/.pkgx/", "/opt/.pkgx", "", false},
		{"/elsewhere/x", "/opt/.pkgx", "", false},
		{"/opt/.pkgx/x", "", "", false},
		{"/opt/.pkgx/acme.org/x", "/opt/.pkgx/", "acme.org/x", true},
	} {
		rest, ok := underDir(tc.p, tc.dir)
		if ok != tc.ok || rest != tc.rest {
			t.Errorf("underDir(%q, %q) = %q, %v; want %q, %v", tc.p, tc.dir, rest, ok, tc.rest, tc.ok)
		}
	}
}

// Without a $ZPKG_DIR — `bk fixup <prefix>` run by hand — the pass does what it
// always did: strip the staging prefix, and nothing else.
func TestNoZpkgDirIsTheOldBehaviour(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "acme.org", "foo", "v1.2.3")
	exe := filepath.Join(prefix, "bin", "foo")
	place(t, exe, machoCmd{lcIDDylib, prefix + "+brewing/lib/libfoo.dylib"})
	if err := FixUp(Options{Prefix: prefix, BuildInstall: prefix + "+brewing", Platform: "darwin"}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != prefix+"/lib/libfoo.dylib" {
		t.Errorf("string = %q", got[0])
	}
}

// A file that is not a Mach-O at all, and one with nothing to rewrite, must
// both come back untouched rather than rewritten or refused.
func TestNothingToDo(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "acme.org", "foo", "v1.2.3")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(prefix, "bin", "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(prefix, "bin", "foo")
	place(t, exe, machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})
	before, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: dir}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a Mach-O with nothing to rewrite was written back")
	}
}

// An unreadable Mach-O must surface as an error rather than as a file quietly
// left absolute — the read that fails here is the one asking what rpaths it has.
func TestRpathReadErrorSurfaces(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "other.org", "bar", "v2.0.0")
	exe := filepath.Join(prefix, "bin", "bar")
	place(t, exe, machoCmd{lcRpath, "@loader_path/../../../.."})
	defer restoreReadFile(os.ReadFile)
	calls := 0
	osReadFile = func(p string) ([]byte, error) {
		calls++
		if calls > 1 { // the first read is isMachO's
			return nil, errInject
		}
		return os.ReadFile(p)
	}
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err == nil {
		t.Fatal("want the read error, got none")
	}
}

// A dependency's MINOR upgrade must not orphan its dependents, which is why the
// reference is major-versioned. Measured on the published gnu.org/grep artifact:
// it named /Users/runner/.pkgx/pcre.org/v2/v10.47/lib/libpcre2-8.0.dylib, the
// machine had pcre2 v10.48, grep could not start — and curl's configure
// reported it as "'grep' utility not found in 'PATH'".
//
// A package's OWN libraries keep their full version: they ship together and
// cannot disagree with each other.
func TestDependencyVersionsAreMajorOnly(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "gnu.org", "grep", "v3.12")
	exe := filepath.Join(prefix, "bin", "grep")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, filepath.Join(zpkgx, "pcre.org/v2/v10.47/lib/libpcre2-8.0.dylib")},
		machoCmd{lcIDDylib, filepath.Join(prefix, "lib/libgreputils.1.dylib")},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != "@rpath/pcre.org/v2/v10/lib/libpcre2-8.0.dylib" {
		t.Errorf("dependency = %q, want it major-versioned", got[1])
	}
	if got[2] != "@rpath/gnu.org/grep/v3.12/lib/libgreputils.1.dylib" {
		t.Errorf("own library = %q, want its full version kept", got[2])
	}
}

// Once a dependency is itself built with an @rpath install name, its dependents
// record @rpath/<project>/v<FULL version>/… — which never reached the
// absolute-path branch, so the version stayed whole and the reference breaks on
// the dependency's next minor release. Measured on the grep artifact rebuilt
// after pcre2 had been: @rpath/pcre.org/v2/v10.48/lib/libpcre2-8.0.dylib.
func TestAlreadyRpathReferencesAreMajorVersionedToo(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "gnu.org", "grep", "v3.12")
	exe := filepath.Join(prefix, "bin", "grep")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, "@rpath/pcre.org/v2/v10.48/lib/libpcre2-8.0.dylib"},
		machoCmd{lcLoadDylib, "@rpath/gnu.org/grep/v3.12/lib/libgreputils.1.dylib"},
		machoCmd{lcLoadDylib, "@rpath/not/under/anything.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "@loader_path/../../../.." {
		t.Errorf("the rpath itself was rewritten: %q", got[0])
	}
	if got[1] != "@rpath/pcre.org/v2/v10/lib/libpcre2-8.0.dylib" {
		t.Errorf("dependency = %q, want it major-versioned", got[1])
	}
	if got[2] != "@rpath/gnu.org/grep/v3.12/lib/libgreputils.1.dylib" {
		t.Errorf("own library = %q, want its full version kept", got[2])
	}
	if got[3] != "@rpath/not/under/anything.dylib" {
		t.Errorf("a reference with no version = %q, want it untouched", got[3])
	}
}

// A Mach-O that references @rpath/… and has NO LC_RPATH loads nowhere, on any
// machine. Found in the published registry — pkgx.sh 2.11.0 references
// @rpath/tukaani.org/xz/v5.8.3/lib/liblzma.5.dylib with zero rpaths and dies
// with "Reason: no LC_RPATH's found" — on an artifact that built, signed,
// attested and published without a complaint.
//
// It happens without anyone writing it: a dependency's install name is what its
// DEPENDENTS record, so the day a library is rebuilt with an @rpath install
// name, everything linking it records @rpath/… too, including a package whose
// own link put no LC_RPATH in.
func TestDeadRpathIsRefused(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe, machoCmd{lcLoadDylib, "@rpath/tukaani.org/xz/v5.8.3/lib/liblzma.5.dylib"})
	err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx})
	if !errors.Is(err, ErrDeadRpath) {
		t.Fatalf("err = %v, want ErrDeadRpath", err)
	}
	if !strings.Contains(err.Error(), "liblzma") {
		t.Errorf("the error must name the reference: %v", err)
	}
}

// With an rpath present the same file is fine: whether that rpath RESOLVES is
// the installer's business, but a file with none can never work.
func TestAnRpathIsEnoughToPass(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, "@rpath/tukaani.org/xz/v5.8.3/lib/liblzma.5.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatalf("a file with an rpath was refused: %v", err)
	}
}

// And a file with no @rpath reference at all is not the case this guards.
func TestNoRpathReferenceNeedsNoRpath(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "acme.org", "thing", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "thing")
	place(t, exe, machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"})
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatalf("a plain binary was refused: %v", err)
	}
}

// TestAnAbsoluteRpathBecomesRelocatable is the llvm.org case. Its darwin
// artifact has, on every one of the 118 Mach-O files that reference a sibling
// package, exactly two rpaths: "@loader_path/../lib" — its own lib directory,
// which cannot reach a sibling — and "/Users/runner/.pkgx", the CI runner's
// home. It loaded on the runner and nowhere else:
//
//	dyld: Library not loaded: @rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib
//	  tried: '/Users/runner/.pkgx/zlib.net/…' (no such file)
//
// and it built, signed, attested and published without a complaint, because the
// old guard asked only whether an LC_RPATH existed.
//
// The guard that caught it is still there, but it no longer has anything to
// say about this file: an absolute rpath INSIDE $ZPKG_DIR states the target,
// the file's own location states the depth, and relativeRpath writes the entry
// that means the same thing from anywhere. What used to be a build refusal is
// now a repair — see TestAbsoluteZpkgxRpathsBecomeLoaderPath for the shape that
// no linker flag could have fixed.
func TestAnAbsoluteRpathBecomesRelocatable(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "llvm.org", "v22.1.8")
	exe := filepath.Join(prefix, "bin", "clang")
	place(t, exe,
		machoCmd{lcRpath, zpkgx},
		machoCmd{lcRpath, "@loader_path/../lib"}, // its own lib, not a sibling's
		machoCmd{lcLoadDylib, "@rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatalf("err = %v; want the builder rpath repaired, not refused", err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "@loader_path/../../.." {
		t.Errorf("rpath = %q, want %q", got[0], "@loader_path/../../..")
	}
}

// What the guard is still for: an absolute rpath that does NOT name anything
// inside $ZPKG_DIR. Homebrew's prefix is a real directory on the build machine
// and a missing one everywhere else, and no arithmetic on the file's own
// location can say where a consumer keeps it — so this is the case that must
// still refuse to publish rather than be guessed at.
func TestAnAbsoluteRpathOutsideZpkgDirStillRefuses(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "llvm.org", "v22.1.8")
	exe := filepath.Join(prefix, "bin", "clang")
	place(t, exe,
		machoCmd{lcRpath, "/opt/homebrew/lib"},
		machoCmd{lcRpath, "@loader_path/../lib"},
		machoCmd{lcLoadDylib, "@rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib"},
	)
	err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx})
	if !errors.Is(err, ErrBuilderOnlyRpath) {
		t.Fatalf("err = %v; want ErrBuilderOnlyRpath", err)
	}
	// The message has to name the reference AND what the file actually carries,
	// or the reader's next step is to run otool themselves.
	if !strings.Contains(err.Error(), "libz.1.3.1.dylib") || !strings.Contains(err.Error(), "@loader_path/../lib") {
		t.Errorf("message hides half the problem: %v", err)
	}
}

// The same file with a relative rpath that DOES reach the pkgx root is fine,
// absolute entry and all: that one is a leak, not a break, and zlib.net,
// sqlite.org and gnome.org/libxml2 are all in that state today.
func TestAnAbsoluteRpathBesideAReachingOneIsAccepted(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "acme.org", "tool", "v1.0.0")
	exe := filepath.Join(prefix, "bin", "tool")
	place(t, exe,
		machoCmd{lcRpath, zpkgx},
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcLoadDylib, "@rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatalf("a reaching relative rpath must be enough: %v", err)
	}
}

// A reference to the package's OWN library needs no rpath out of the package,
// and must not be mistaken for a sibling: the version directory is what tells
// them apart.
func TestOwnLibraryReferenceNeedsNoEscapingRpath(t *testing.T) {
	zpkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkgx, "llvm.org", "v22.1.8")
	exe := filepath.Join(prefix, "bin", "clang")
	place(t, exe,
		machoCmd{lcRpath, "@loader_path/../lib"},
		machoCmd{lcLoadDylib, "@rpath/libLLVM.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkgx}); err != nil {
		t.Fatalf("own-library reference must be accepted: %v", err)
	}
}

func TestSiblingRef(t *testing.T) {
	for s, want := range map[string]bool{
		"@rpath/zlib.net/v1.3.1/lib/libz.1.3.1.dylib": true,
		"@rpath/gnu.org/gcc/v14/lib/libgcc_s.1.dylib": true,
		"@rpath/libLLVM.dylib":                        false,
		"@rpath/lib/libfoo.dylib":                     false,
		// A directory that merely starts with v is not a version.
		"@rpath/vendor/libfoo.dylib": false,
	} {
		if got := siblingRef(s); got != want {
			t.Errorf("siblingRef(%q) = %v, want %v", s, got, want)
		}
	}
}
