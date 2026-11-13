package fixup

import (
	"path/filepath"
	"strings"
	"testing"
)

// bundleUnder is where gnu.org/help2man's perl XS actually installs, relative
// to its prefix: NINE levels down. The depth is the point — bk links in
// @loader_path depths 4 through 8, measured for <prefix>/bin and <prefix>/lib,
// and nothing it can emit at link time reaches this far.
const bundleUnder = "lib/perl5/darwin-thread-multi-2level/auto/Locale/gettext/gettext.bundle"

// An artifact whose references are relocated but whose SEARCH ROOTS are the build
// machine's runs on the build machine and nowhere else. This is the shape that
// failed gnu.org/help2man 1.49.3's rebuild, reproduced from its guard message:
//
//	gettext.bundle references @rpath/gnu.org/gettext/v1/lib/libintl.8.dylib
//	but its only rpaths are /Users/runner/.pkgx,
//	/Users/runner/.pkgx/gnu.org/gettext/v1.0.0/lib
func TestAbsoluteZpkxRpathsBecomeLoaderPath(t *testing.T) {
	zpkx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkx, "gnu.org", "help2man", "v1.49.3")
	exe := filepath.Join(prefix, bundleUnder)
	placePad(t, exe, 256,
		machoCmd{lcRpath, zpkx},
		machoCmd{lcRpath, filepath.Join(zpkx, "gnu.org/gettext/v1.0.0/lib")},
		machoCmd{lcLoadDylib, "@rpath/gnu.org/gettext/v1/lib/libintl.8.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	// Nine levels from the bundle's own directory back to $ZPKG_DIR.
	up := strings.TrimSuffix(strings.Repeat("../", 9), "/")
	want := []string{
		"@loader_path/" + up,
		// Not up+"/gnu.org/…": the two packages share a gnu.org directory, so
		// the shortest path between them climbs only as far as that.
		"@loader_path/" + strings.TrimSuffix(strings.Repeat("../", 8), "/") + "/gettext/v1.0.0/lib",
		"@rpath/gnu.org/gettext/v1/lib/libintl.8.dylib", // already right; left alone
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("string %d = %q, want %q", i, got[i], want[i])
		}
	}
	// The guard that refused the build is the judge that it is fixed.
	checked, problems := AuditRelocatable(prefix, zpkx)
	if checked == 0 {
		t.Fatal("audit checked nothing; it cannot have judged the bundle")
	}
	for _, p := range problems {
		t.Errorf("audit still refuses: %v", p)
	}
}

// An rpath outside $ZPKG_DIR names something the artifact does not carry and did
// not build — making it relative would point it at the wrong tree.
func TestRpathsOutsideZpkgDirAreLeftAlone(t *testing.T) {
	zpkx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkx, "acme.org", "foo", "v1.0.0")
	exe := filepath.Join(prefix, "lib", "libfoo.dylib")
	placePad(t, exe, 256,
		machoCmd{lcRpath, "/usr/local/lib"},
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcRpath, zpkx + "-other"}, // a sibling directory, not this one
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/local/lib", "@loader_path/../../../..", zpkx + "-other", "/usr/lib/libSystem.B.dylib"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("string %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRelativeRpathRefusals(t *testing.T) {
	zpkx := "/x/.pkgx"
	exe := "/x/.pkgx/a.org/b/v1/lib/l.dylib"
	for _, c := range []struct {
		name, exe, rpath, zpkx string
	}{
		{"no pkgx dir", exe, zpkx, ""},
		{"already relative", exe, "@loader_path/../..", zpkx},
		{"outside the tree", exe, "/usr/lib", zpkx},
		{"file outside the tree", "/elsewhere/l.dylib", zpkx, zpkx},
		// A relative exe is refused up front: it is what makes the
		// filepath.Rel inside total.
		{"relative file", "l.dylib", zpkx, zpkx},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := relativeRpath(c.exe, c.rpath, c.zpkx)
			if ok {
				t.Errorf("rewrote to %q, want it refused", got)
			}
			if got != c.rpath {
				t.Errorf("returned %q, want the input %q unchanged", got, c.rpath)
			}
		})
	}
	// $ZPKG_DIR itself, as the rpath of a file sitting directly in it.
	if got, ok := relativeRpath("/x/.pkgx/l.dylib", zpkx, zpkx); !ok || got != "@loader_path" {
		t.Errorf("own directory = %q, %v; want \"@loader_path\", true", got, ok)
	}
}

// Relativising an absolute rpath can produce a string the file ALREADY has,
// and a duplicate LC_RPATH is fatal to everything downstream:
//
//	ld: duplicate LC_RPATH '@loader_path/../../../..' in
//	    .../facebook.com/folly/v2026.09.14.00/lib/libfolly.0.58.0-dev.dylib
//	c++: error: linker command failed with exit code 1
//
// Measured on an artifact this factory published after the relativisation landed:
// libfolly carried @loader_path/../../../.. twice — one linked in by bk, one
// written by the rewrite — and github.com/facebookincubator/fizz could not link
// against it at all.
//
// Leaving the absolute entry keeps a builder path in the artefact, which is a
// leak. Writing the duplicate breaks every dependent, which is a break. The
// guard's requirement — a relative rpath that reaches $ZPKG_DIR — is satisfied
// either way, because the one that would have been duplicated is already there.
func TestARelativisedRpathIsNotWrittenTwice(t *testing.T) {
	zpkx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(zpkx, "acme.org", "foo", "v1.0.0")
	exe := filepath.Join(prefix, "lib", "libfoo.dylib")
	placePad(t, exe, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."}, // bk's, and the depth of this file
		machoCmd{lcRpath, zpkx},
		machoCmd{lcLoadDylib, "@rpath/other.org/bar/v1/lib/libbar.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: zpkx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(exe)
	if err != nil {
		t.Fatal(err)
	}
	var rpaths []string
	for _, s := range got {
		if strings.HasPrefix(s, "@loader_path") || filepath.IsAbs(s) {
			rpaths = append(rpaths, s)
		}
	}
	seen := map[string]int{}
	for _, r := range rpaths {
		seen[r]++
	}
	for r, n := range seen {
		if n > 1 {
			t.Errorf("rpath %q appears %d times; ld refuses a duplicate LC_RPATH", r, n)
		}
	}
	// The absolute one is not half-written either: it is REMOVED (bk#395), since
	// the relative entry that means the same thing is already there.
	for _, s := range got {
		if s == zpkx {
			t.Errorf("builder path %q survived", zpkx)
		}
	}
	// The guard is satisfied all the same: a relative rpath reaches the root.
	checked, problems := AuditRelocatable(prefix, zpkx)
	if checked == 0 {
		t.Fatal("audit checked nothing")
	}
	for _, p := range problems {
		t.Errorf("audit refuses: %v", p)
	}
}
