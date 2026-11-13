package fixup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mpdecimal's case, end to end and without a linker so every lane runs it: a
// library with NO rpath at all, naming a sibling by bare soname. Every other
// repair here produces another @rpath reference, which resolves nowhere when
// there is no LC_RPATH to search — so the build was refused, correctly and
// with no way forward.
func TestBareSiblingIsAnsweredWithLoaderPath(t *testing.T) {
	zpkx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkx, "bytereef.org", "mpdecimal", "v2.5.1")
	lib := filepath.Join(prefix, "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	// The sibling it names, really there.
	place(t, filepath.Join(lib, "libmpdec.3.dylib"))
	exe := filepath.Join(lib, "libmpdec++.2.5.1.dylib")
	// Padded, as the real artifact is: @loader_path/ is six bytes longer than
	// @rpath/, and a load-command string cannot grow past the header padding.
	// Measured on the published libmpdec++.2.5.1.dylib: 16376 bytes spare.
	placePad(t, exe, 64, machoCmd{lcLoadDylib, "@rpath/libmpdec.3.dylib"}) // and no lcRpath

	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if s == "@loader_path/libmpdec.3.dylib" {
			return
		}
	}
	t.Errorf("no reference is @loader_path/libmpdec.3.dylib; the file records %v", got)
}

// A binary in bin/ naming a library that ships in the package's lib/ gets the
// path from where IT sits, not from the prefix: @loader_path is relative to
// the referring file.
func TestBareNameFromBinGetsTheRelativePath(t *testing.T) {
	zpkx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkx, "a.org", "v1.0.0")
	if err := os.MkdirAll(filepath.Join(prefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	place(t, filepath.Join(prefix, "lib", "liba.1.dylib"))
	exe := filepath.Join(prefix, "bin", "tool")
	placePad(t, exe, 64, machoCmd{lcLoadDylib, "@rpath/liba.1.dylib"})

	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkx}); err != nil {
		t.Fatal(err)
	}
	got, _ := ReadMachoStrings(exe)
	for _, s := range got {
		if s == "@loader_path/../lib/liba.1.dylib" {
			return
		}
	}
	t.Errorf("references: %v", got)
}

// A name the package does not ship is NOT answered. Inventing a location for a
// dependency's library is what the closure-owner search is for, and that one
// needs an rpath to resolve through.
func TestBareNameThatIsNotOursIsLeftAlone(t *testing.T) {
	zpkx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkx, "a.org", "v1.0.0")
	if err := os.MkdirAll(filepath.Join(prefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(prefix, "lib", "liba.1.dylib")
	place(t, exe, machoCmd{lcLoadDylib, "@rpath/libsomeoneelse.7.dylib"})

	// The build is REFUSED, which is right: the reference resolves nowhere and
	// nothing here can make it. What must not happen is a repair invented out
	// of a name we do not own.
	err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkx})
	if err == nil {
		t.Fatal("a file whose reference resolves nowhere was accepted")
	}
	if !strings.Contains(err.Error(), "libsomeoneelse.7.dylib") {
		t.Errorf("the refusal does not name the reference: %v", err)
	}
	got, _ := ReadMachoStrings(exe)
	for _, s := range got {
		if strings.HasPrefix(s, "@loader_path") {
			t.Errorf("a reference we do not own was invented: %v", got)
		}
	}
}

// The unit, at its edges: a reference that is not bare, and one that is empty,
// are not this function's business.
func TestLoaderPathRefRefusesWhatIsNotABareName(t *testing.T) {
	opts := Options{Prefix: t.TempDir()}
	for _, ref := range []string{
		"@rpath/a.org/v1/lib/liba.dylib", // already qualified
		"@rpath/",                        // nothing named
		"/usr/lib/libSystem.B.dylib",     // not an @rpath reference
		"@loader_path/liba.dylib",        // already answered
	} {
		if got, ok := loaderPathRef("/x/y", ref, opts); ok {
			t.Errorf("loaderPathRef(%q) = %q, want no answer", ref, got)
		}
	}
}

// A RELATIVE Prefix with an absolute file is a caller that has not resolved
// its own paths. filepath.Rel cannot answer across that boundary, and the
// reference is left alone rather than given a path computed from the working
// directory — which would be right only until something changed directory.
func TestLoaderPathRefWithARelativePrefix(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll("lib", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("lib", "liba.1.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// exe is absolute, Prefix is not.
	exe := filepath.Join(dir, "elsewhere", "bin", "tool")
	if got, ok := loaderPathRef(exe, "@rpath/liba.1.dylib", Options{Prefix: "."}); ok {
		t.Errorf("loaderPathRef = %q, want no answer across a relative prefix", got)
	}
}
