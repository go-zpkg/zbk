package fixup

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// An ELF states its ABI name in DT_SONAME, and the basename is what ld.so
// matches on.
func TestSonameOfELF(t *testing.T) {
	p := buildELFTag(t, elf.DT_SONAME, "/build/dir/libfoo.so.1", "libc.so.6", 32)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := SonameOf(raw); got != "libfoo.so.1" {
		t.Errorf("SonameOf = %q, want libfoo.so.1", got)
	}
}

// An ELF with no DT_SONAME is not a shared library anyone binds to by name.
func TestSonameOfELFWithout(t *testing.T) {
	p := buildELF64LE(t, "$ORIGIN/../lib", "libc.so.6", 32)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := SonameOf(raw); got != "" {
		t.Errorf("SonameOf = %q, want empty", got)
	}
}

// Anything that is not an object file at all — a script, an archive, a
// truncated read — yields nothing rather than an error: an artifact is full of
// them and none is a shared library.
func TestSonameOfNonObject(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		[]byte("#!/bin/sh\necho hi\n"),
		[]byte("!<arch>\n"),
		[]byte("\x7fELF truncated"),
		[]byte{0xcf, 0xfa, 0xed, 0xfe}, // Mach-O magic and nothing after it
	} {
		if got := SonameOf(b); got != "" {
			t.Errorf("SonameOf(%q) = %q, want empty", b, got)
		}
	}
}

func TestSortedUnique(t *testing.T) {
	got := SortedUnique([]string{"libz.1.dylib", "", "libа.dylib", "libz.1.dylib", "liba.dylib"})
	want := []string{"liba.dylib", "libz.1.dylib", "libа.dylib"}
	if len(got) != len(want) {
		t.Fatalf("SortedUnique = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SortedUnique = %v, want %v", got, want)
		}
	}
}

// The Mach-O side, without needing a linker — so the linux lane exercises it
// too. The install name carries a directory and the soname is its last
// component: the path is where this build put the file, the basename is what
// dyld matches on.
func TestSonameOfMachOFixture(t *testing.T) {
	p := buildMachO(t, machoCmd{lcIDDylib, "@rpath/zlib.net/v1/lib/libz.1.dylib"})
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := SonameOf(raw); got != "libz.1.dylib" {
		t.Errorf("SonameOf = %q, want libz.1.dylib", got)
	}
}

// A Mach-O with no LC_ID_DYLIB is an executable or a bundle: nothing binds to
// it by name.
func TestSonameOfMachOWithoutAnID(t *testing.T) {
	p := buildMachO(t, machoCmd{lcLoadDylib, "@rpath/other/v1/lib/libother.1.dylib"})
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := SonameOf(raw); got != "" {
		t.Errorf("SonameOf = %q, want empty", got)
	}
}

// A universal binary carries the same ID in each slice; the first one answers.
func TestSonameOfFatMachO(t *testing.T) {
	p := buildFatMachO(t,
		[]machoCmd{{lcIDDylib, "@rpath/a/v1/lib/libfat.2.dylib"}},
		[]machoCmd{{lcIDDylib, "@rpath/a/v1/lib/libfat.2.dylib"}},
	)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := SonameOf(raw); got != "libfat.2.dylib" {
		t.Errorf("SonameOf = %q, want libfat.2.dylib", got)
	}
}

// MachoNeeded is what a file LOADS. The install name is not a dependency:
// counting it makes a library appear to depend on wherever it happens to live,
// which is what made bk's undeclared sweep report a self-edge on its first run.
func TestMachoNeededExcludesTheInstallName(t *testing.T) {
	p := buildMachO(t,
		machoCmd{lcIDDylib, "@rpath/acme.org/thing/v1/lib/libthing.1.dylib"},
		machoCmd{lcLoadDylib, "@rpath/other.org/dep/v2/lib/libdep.2.dylib"},
		machoCmd{lcRpath, "@loader_path/../../.."},
	)
	got, err := MachoNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "@rpath/other.org/dep/v2/lib/libdep.2.dylib" {
		t.Fatalf("MachoNeeded = %v, want only the loaded dylib", got)
	}
}

// A file that is not a Mach-O is an error, not an empty list: the caller skips
// it, and "no dependencies" would be a claim.
func TestMachoNeededOnANonMachO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := MachoNeeded(p); err == nil {
		t.Error("a shell script read as a Mach-O")
	}
}
