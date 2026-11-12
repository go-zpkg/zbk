package fixup

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMachOPad writes a Mach-O whose load commands are followed by pad bytes
// of slack before the first section's file data — the headroom a real linker
// leaves, and the only reason a load command can be made longer in place.
//
// It appends one __TEXT segment carrying one section. That command holds no
// string, so it does not disturb the index of anything ReadMachoStrings
// returns.
func buildMachOPad(t *testing.T, pad int, cmds ...machoCmd) string {
	t.Helper()
	le := binary.LittleEndian
	var body []byte
	for _, c := range cmds {
		strOff := 24
		if c.cmd == lcRpath {
			strOff = 12
		}
		size := strOff + len(c.str) + 1
		for size%8 != 0 {
			size++
		}
		cb := make([]byte, size)
		le.PutUint32(cb[0:], c.cmd)
		le.PutUint32(cb[4:], uint32(size))
		le.PutUint32(cb[8:], uint32(strOff))
		copy(cb[strOff:], c.str)
		body = append(body, cb...)
	}
	const (
		lcSegment64 = 0x19
		segCmdSize  = 72 + 80
	)
	seg := make([]byte, segCmdSize)
	le.PutUint32(seg[0:], lcSegment64)
	le.PutUint32(seg[4:], segCmdSize)
	copy(seg[8:], "__TEXT")
	le.PutUint32(seg[64:], 1) // nsects
	copy(seg[72:], "__text")
	copy(seg[72+16:], "__TEXT")
	body = append(body, seg...)

	sectOff := 32 + len(body) + pad
	le.PutUint32(body[len(body)-80+48:], uint32(sectOff)) // section_64.offset
	le.PutUint64(body[len(body)-80+32:], 16)              // section_64.size

	buf := make([]byte, sectOff+16)
	le.PutUint32(buf[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(buf[4:], 0x0100000c) // CPU_TYPE_ARM64
	le.PutUint32(buf[12:], 6)         // MH_DYLIB
	le.PutUint32(buf[16:], uint32(len(cmds)+1))
	le.PutUint32(buf[20:], uint32(len(body)))
	copy(buf[32:], body)
	le.PutUint64(buf[32+len(body)-segCmdSize+40:], uint64(len(buf))) // segment filesize
	p := filepath.Join(t.TempDir(), "obj.dylib")
	if err := os.WriteFile(p, buf, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func placePad(t *testing.T, path string, pad int, cmds ...machoCmd) {
	t.Helper()
	b, err := os.ReadFile(buildMachOPad(t, pad, cmds...))
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

// CMake's default install name on darwin is @rpath/<soname> — a BARE name, with
// no directory at all. A consumer's rpath reaches $ZPKG_DIR, not the library's
// own lib dir, so that name resolves nowhere:
//
//	dyld: Library not loaded: @rpath/libzstd.1.dylib
//
// Measured on our published facebook.com/zstd bottle, which aborted llvm.org's
// darwin build at dyld time (#125); upstream pkgx's bottle for the same version
// carries the qualified form.
//
// The soname LEAF is kept, because the symlink carrying it ships beside the
// library — so consumers keep binding to libzstd.1.dylib, not to
// libzstd.1.5.7.dylib. The correct name is LONGER than the wrong one, so this
// only works because a load command can now grow into the linker's slack.
func TestBareInstallNameGainsItsDirectory(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "facebook.com", "zstd", "v1.5.7")
	lib := filepath.Join(prefix, "lib", "libzstd.1.5.7.dylib")
	placePad(t, lib, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcIDDylib, "@rpath/libzstd.1.dylib"},
	)
	if err := os.Symlink("libzstd.1.5.7.dylib", filepath.Join(prefix, "lib", "libzstd.1.dylib")); err != nil {
		t.Fatal(err)
	}
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	const want = "@rpath/facebook.com/zstd/v1.5.7/lib/libzstd.1.dylib"
	if got[1] != want {
		t.Errorf("install name = %q, want %q", got[1], want)
	}
	if got[0] != "@loader_path/../../../.." {
		t.Errorf("rpath = %q, want it untouched", got[0])
	}
}

// A soname with no symlink beside it is a name we would be inventing. The
// file's own name is the one thing known to exist.
func TestBareInstallNameFallsBackToTheFileItself(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.2.3")
	lib := filepath.Join(prefix, "lib", "libfoo.1.2.3.dylib")
	placePad(t, lib, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcIDDylib, "@rpath/libfoo.1.dylib"},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	const want = "@rpath/acme.org/foo/v1.2.3/lib/libfoo.1.2.3.dylib"
	if got[1] != want {
		t.Errorf("install name = %q, want %q", got[1], want)
	}
}

// An install name that already names a directory was either written correctly
// or is the absolute case handled elsewhere. Only a bare one is touched.
func TestQualifiedInstallNameIsLeftAlone(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.2.3")
	lib := filepath.Join(prefix, "lib", "libfoo.dylib")
	const id = "@rpath/acme.org/foo/v1.2.3/lib/libfoo.dylib"
	placePad(t, lib, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcIDDylib, id},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != id {
		t.Errorf("install name = %q, want it unchanged", got[1])
	}
}

// With no slack there is nowhere to grow into, and the answer is the one this
// code always gave: leave it, do not corrupt it. A build linked without
// -headerpad_max_install_names can land here.
//
// Run against a padded twin, because "unchanged" is also what a rewrite that
// never fired would produce — the same fixture with slack must change.
func TestBareInstallNameWithNoHeadroomIsLeftAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		pad  int
		want string
	}{
		{"no slack", 0, "@rpath/libfoo.dylib"},
		{"slack", 256, "@rpath/acme.org/foo/v1.2.3/lib/libfoo.dylib"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkgx := filepath.Join(t.TempDir(), ".pkgx")
			prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.2.3")
			lib := filepath.Join(prefix, "lib", "libfoo.dylib")
			placePad(t, lib, tc.pad,
				machoCmd{lcRpath, "@loader_path/../../../.."},
				machoCmd{lcIDDylib, "@rpath/libfoo.dylib"},
			)
			if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
				t.Fatal(err)
			}
			got, err := ReadMachoStrings(lib)
			if err != nil {
				t.Fatal(err)
			}
			if got[1] != tc.want {
				t.Errorf("install name = %q, want %q", got[1], tc.want)
			}
		})
	}
}

// Growing one command must leave every OTHER string in the file exactly where
// the reader expects it: the commands after it slide down, sizeofcmds rises,
// and nothing else in the file moves.
func TestGrowthKeepsTheRestOfTheLoadCommandsReadable(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.2.3")
	lib := filepath.Join(prefix, "lib", "libfoo.dylib")
	placePad(t, lib, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcIDDylib, "@rpath/libfoo.dylib"},
		machoCmd{lcLoadDylib, filepath.Join(pkgx, "other.org/bar/v2.0.0/lib/libbar.dylib")},
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)
	before, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("file size = %d, was %d: growth must stay inside the slack", len(after), len(before))
	}
	le := binary.LittleEndian
	if grew := le.Uint32(after[20:]) - le.Uint32(before[20:]); grew == 0 {
		t.Error("sizeofcmds did not rise, so nothing grew")
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"@loader_path/../../../..",
		"@rpath/acme.org/foo/v1.2.3/lib/libfoo.dylib",
		"@rpath/other.org/bar/v2/lib/libbar.dylib",
		"/usr/lib/libSystem.B.dylib",
	}
	if len(got) != len(want) {
		t.Fatalf("read %d strings, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("string %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The growth primitives, at their edges. These are the branches that keep a
// malformed or unusual Mach-O from being rewritten into rubble, and none of
// them is reachable through a well-formed fixture — which is the point.
func TestGrowMachoCmdRefusals(t *testing.T) {
	le := binary.LittleEndian
	t.Run("32-bit slice", func(t *testing.T) {
		raw := make([]byte, 64)
		if _, err := growMachoCmd(raw, le, 28, 1, 28, 200); err != ErrNoSpace {
			t.Errorf("err = %v, want ErrNoSpace: a 32-bit slice is not grown", err)
		}
	})
	t.Run("already long enough", func(t *testing.T) {
		raw := make([]byte, 64)
		le.PutUint32(raw[32+4:], 32) // cmdsize
		got, err := growMachoCmd(raw, le, 32, 1, 32, 24)
		if got != 0 || err != nil {
			t.Errorf("grew %d, %v; want 0, nil when the string already fits", got, err)
		}
	})
	t.Run("no section to bound the commands", func(t *testing.T) {
		raw := make([]byte, 128)
		le.PutUint32(raw[20:], 16) // sizeofcmds
		le.PutUint32(raw[32+4:], 16)
		if _, err := growMachoCmd(raw, le, 32, 1, 32, 200); err != ErrNoSpace {
			t.Errorf("err = %v, want ErrNoSpace with no section offset to grow up to", err)
		}
	})
}

// machoCmdLimit reads section offsets out of the segment commands. A truncated
// or self-contradicting one must make it give up rather than read past the end
// or trust a number it cannot check.
func TestMachoCmdLimitRefusesMalformedCommands(t *testing.T) {
	le := binary.LittleEndian
	t.Run("impossible cmdsize", func(t *testing.T) {
		raw := make([]byte, 64)
		le.PutUint32(raw[32:], 0x19)
		le.PutUint32(raw[32+4:], 4) // < 8
		if _, ok := machoCmdLimit(raw, le, 32, 1); ok {
			t.Error("accepted a load command smaller than its own header")
		}
	})
	t.Run("more sections than the command holds", func(t *testing.T) {
		raw := make([]byte, 256)
		le.PutUint32(raw[32:], 0x19)
		le.PutUint32(raw[32+4:], 72+80) // room for one section
		le.PutUint32(raw[32+64:], 4)    // claims four
		if _, ok := machoCmdLimit(raw, le, 32, 1); ok {
			t.Error("accepted a segment claiming more sections than it has room for")
		}
	})
	t.Run("zero-fill sections bound nothing", func(t *testing.T) {
		raw := make([]byte, 512)
		le.PutUint32(raw[32:], 0x19)
		le.PutUint32(raw[32+4:], 72+160) // two sections
		le.PutUint32(raw[32+64:], 2)
		le.PutUint32(raw[32+72+48:], 0)    // __bss: no file bytes
		le.PutUint32(raw[32+72+80+48:], 9) // __text
		got, ok := machoCmdLimit(raw, le, 32, 1)
		if !ok || got != 9 {
			t.Errorf("limit = %d, %v; want 9, true — a zero offset is not a bound", got, ok)
		}
	})
}

// A dylib installed outside $ZPKG_DIR has no qualified name to be given: there
// is no directory to name it relative to. With no $ZPKG_DIR at all there is not
// even a question to answer — unreachable through FixUp, which only calls this
// once an rpath has been shown to reach $ZPKG_DIR, so it is asserted directly.
func TestQualifyIDOutsideZpkgDir(t *testing.T) {
	if _, ok := qualifyID("/elsewhere/lib/libfoo.dylib", "@rpath/libfoo.dylib", Options{ZpkgDir: "/opt/pkgx"}); ok {
		t.Error("qualified an install name for a file that is not under $ZPKG_DIR")
	}
	if _, ok := qualifyID("/opt/pkgx/a/v1/lib/libfoo.dylib", "@rpath/libfoo.dylib", Options{}); ok {
		t.Error("qualified an install name with no $ZPKG_DIR to name it against")
	}
}

// A hand-written Makefile leaves a plain soname with no prefix at all —
// sourceware.org/bzip2 ships libbz2.1.0.8.dylib whose install name is the bare
// string "libbz2.dylib". It resolves in the pkgx layout exactly as well as the
// @rpath/ spelling does, which is to say not at all, and bzip2's own binary
// hides it by linking the static archive: only a package that links libbz2
// finds out.
func TestPlainRelativeInstallNameGainsItsDirectory(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "sourceware.org", "bzip2", "v1.0.8")
	lib := filepath.Join(prefix, "lib", "libbz2.1.0.8.dylib")
	placePad(t, lib, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcIDDylib, "libbz2.dylib"},
	)
	if err := os.Symlink("libbz2.1.0.8.dylib", filepath.Join(prefix, "lib", "libbz2.dylib")); err != nil {
		t.Fatal(err)
	}
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	const want = "@rpath/sourceware.org/bzip2/v1.0.8/lib/libbz2.dylib"
	if got[1] != want {
		t.Errorf("install name = %q, want %q", got[1], want)
	}
}

// @loader_path and @executable_path install names are already anchored to
// something real. Rewriting one would move a reference that works.
func TestLoaderPathInstallNameIsLeftAlone(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.2.3")
	lib := filepath.Join(prefix, "lib", "libfoo.dylib")
	const id = "@loader_path/../lib/libfoo.dylib"
	placePad(t, lib, 256,
		machoCmd{lcRpath, "@loader_path/../../../.."},
		machoCmd{lcIDDylib, id},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != id {
		t.Errorf("install name = %q, want it unchanged", got[1])
	}
}

// A library that links nothing outside its own package never gets a
// $ZPKG_DIR-reaching rpath, because it needs none. Gating the install-name fix
// on that rpath therefore skipped exactly the files whose id was least likely
// to be repaired any other way: sourceware.org/bzip2's libbz2.1.0.8.dylib links
// only libSystem, and came back from a repair rebuild still carrying
// "libbz2.dylib".
//
// An install name says where THIS file is. Whether it resolves is the
// CONSUMER's rpath's business, and qualifying it is never worse than leaving it
// — a consumer without a $ZPKG_DIR rpath fails on either spelling.
func TestInstallNameIsFixedWithoutAnRpathOfItsOwn(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "sourceware.org", "bzip2", "v1.0.8")
	lib := filepath.Join(prefix, "lib", "libbz2.1.0.8.dylib")
	placePad(t, lib, 256,
		machoCmd{lcIDDylib, "libbz2.dylib"},
		machoCmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)
	if err := os.Symlink("libbz2.1.0.8.dylib", filepath.Join(prefix, "lib", "libbz2.dylib")); err != nil {
		t.Fatal(err)
	}
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	const want = "@rpath/sourceware.org/bzip2/v1.0.8/lib/libbz2.dylib"
	if got[0] != want {
		t.Errorf("install name = %q, want %q", got[0], want)
	}
	// The OS reference is not ours to touch, rpath or no rpath.
	if got[1] != "/usr/lib/libSystem.B.dylib" {
		t.Errorf("system reference = %q, want it untouched", got[1])
	}
}

// The rest of the relocation still needs a reachable rpath. A file with an
// absolute reference into $ZPKG_DIR and no way back to it keeps that
// reference — @rpath would resolve nowhere, which is worse than a path that at
// least works in one place.
func TestReferencesStillNeedAnRpathEvenWhenTheIDIsFixed(t *testing.T) {
	pkgx := filepath.Join(t.TempDir(), ".pkgx")
	prefix := filepath.Join(pkgx, "acme.org", "foo", "v1.2.3")
	lib := filepath.Join(prefix, "lib", "libfoo.dylib")
	dep := filepath.Join(pkgx, "other.org/bar/v2.0.0/lib/libbar.dylib")
	placePad(t, lib, 256,
		machoCmd{lcIDDylib, "libfoo.dylib"},
		machoCmd{lcLoadDylib, dep},
	)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", ZpkgDir: pkgx}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMachoStrings(lib)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "@rpath/acme.org/foo/v1.2.3/lib/libfoo.dylib" {
		t.Errorf("install name = %q, want it qualified", got[0])
	}
	if got[1] != dep {
		t.Errorf("dependency = %q, want it left absolute for lack of an rpath", got[1])
	}
}

// machoID answers "" for anything it cannot read, so the caller's question —
// "is there an install name to fix here?" — has a usable answer for an
// executable, a bundle, or a file that is not Mach-O at all.
func TestMachoIDOfSomethingUnreadable(t *testing.T) {
	if got := machoID(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("machoID of a missing file = %q, want empty", got)
	}
}

// A bare @rpath/<soname> REFERENCE — no directory — resolves nowhere in the
// pkgx layout: an rpath entry points at $ZPKG_DIR or at a package root, never
// at a lib dir, so dyld joins the soname onto a directory that does not hold
// it. qualifyID fixes the library's own name, which only helps whatever links
// it AFTERWARDS; every dependent already built carries the bare string.
//
// Measured on the published catalogue, where the reference and the file it
// wants ship in the SAME package:
//
//	libjpeg-turbo.org      bin/cjpeg                  -> @rpath/libjpeg.8.dylib
//	bytereef.org/mpdecimal lib/libmpdec++.2.5.1.dylib -> @rpath/libmpdec.3.dylib
//
// cjpeg does not start at all. Across 2319 Mach-O files in installed closures,
// 124 carried a bare reference and 102 of them resolved to nothing.
func TestQualifyBareReferenceToOwnPackage(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "libjpeg-turbo.org", "v3.2.0")
	if err := os.MkdirAll(filepath.Join(prefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the library the reference means, one directory away from the binary
	if err := os.WriteFile(filepath.Join(prefix, "lib", "libjpeg.8.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	exe := buildMachOPad(t, 256,
		machoCmd{lcLoadDylib, "@rpath/libjpeg.8.dylib"},
		machoCmd{lcRpath, "@loader_path/../../.."},
	)
	bin := filepath.Join(prefix, "bin", "cjpeg")
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := rewriteMacho(bin, Options{Prefix: prefix, ZpkgDir: pkgx, Platform: "darwin"}); err != nil {
		t.Fatal(err)
	}
	strs, err := readMachoRefs(bin)
	if err != nil {
		t.Fatal(err)
	}
	want := "@rpath/libjpeg-turbo.org/v3.2.0/lib/libjpeg.8.dylib"
	for _, s := range strs {
		if s == want {
			return
		}
	}
	t.Errorf("references = %v\nwant one of them to be %q", strs, want)
}

// Nothing is invented. A bare soname whose file is in neither the referring
// file's directory nor the package's lib belongs to some dependency, and which
// one is not something to guess at — the string is left exactly as it was.
func TestBareReferenceToAnotherPackageIsLeftAlone(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "simplesystems.org", "libtiff", "v4.7.2")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := buildMachOPad(t, 256,
		machoCmd{lcLoadDylib, "@rpath/libzstd.1.dylib"}, // zstd is a DEPENDENCY
		machoCmd{lcRpath, "@loader_path/../../../.."},
	)
	bin := filepath.Join(prefix, "bin", "tiffsplit")
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rewriteMacho(bin, Options{Prefix: prefix, ZpkgDir: pkgx, Platform: "darwin"}); err != nil {
		t.Fatal(err)
	}
	strs, err := readMachoRefs(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range strs {
		if s == "@rpath/libzstd.1.dylib" {
			return
		}
	}
	t.Errorf("references = %v\nwant @rpath/libzstd.1.dylib kept verbatim", strs)
}

// While a build is still writing, the file is under the +brewing staging
// prefix and the name it must be given is the final one. qualifyRef stats
// where the bytes ARE and writes where they WILL BE; a lookup that only knew
// one of the two would answer "no such library" for every package fixed up
// before it is moved into place.
func TestQualifyBareReferenceFindsTheStagedFile(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "bytereef.org", "mpdecimal", "v2.5.1")
	staging := filepath.Join(pkgx, "bytereef.org", "mpdecimal", "v2.5.1+brewing")
	if err := os.MkdirAll(filepath.Join(staging, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	// the library exists ONLY under the staging prefix
	if err := os.WriteFile(filepath.Join(staging, "lib", "libmpdec.3.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := qualifyRef(
		filepath.Join(staging, "lib", "libmpdec++.2.5.1.dylib"),
		"libmpdec.3.dylib",
		Options{Prefix: prefix, BuildInstall: staging, ZpkgDir: pkgx},
	)
	want := "@rpath/bytereef.org/mpdecimal/v2.5.1/lib/libmpdec.3.dylib"
	if !ok || got != want {
		t.Errorf("qualifyRef = %q, %v\nwant %q, true", got, ok, want)
	}
}

// A bare soname that belongs to a DEPENDENCY is answered by the closure, not
// guessed: the library is staged under $ZPKG_DIR, and if exactly one project
// there ships that file, that is where it came from.
//
// simplesystems.org/libtiff is the measured case — bin/tiffsplit asks for
// @rpath/libzstd.1.dylib, facebook.com/zstd ships it, and nothing else in the
// closure does. Across the installed closures of 44 packages, 76 of the 102
// unresolvable bare references had exactly one owning project and none had
// two; 60 of the 76 were this same libzstd.1.dylib, zstd's bare install name
// still being recorded by consumers.
func TestQualifyBareReferenceAgainstTheClosure(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "simplesystems.org", "libtiff", "v4.7.2")
	dep := filepath.Join(pkgx, "facebook.com", "zstd", "v1.5.7", "lib")
	for _, d := range []string{filepath.Join(prefix, "bin"), dep} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dep, "libzstd.1.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := qualifyRef(filepath.Join(prefix, "bin", "tiffsplit"), "libzstd.1.dylib",
		Options{Prefix: prefix, ZpkgDir: pkgx})
	// the MAJOR directory, as every other sibling reference is written: v1
	// resolves to whatever 1.x the machine has, so a dependency's minor
	// upgrade does not orphan its dependents.
	want := "@rpath/facebook.com/zstd/v1/lib/libzstd.1.dylib"
	if !ok || got != want {
		t.Errorf("qualifyRef = %q, %v\nwant %q, true", got, ok, want)
	}
}

// Two projects shipping one soname is a question about which one this binary
// was linked against, and nothing in a Mach-O records the answer. Declining is
// the only honest move: a reference invented from the wrong project would load
// and behave, which is worse than one that fails loudly.
func TestBareReferenceWithTwoOwnersIsDeclined(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "a.org", "v1")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(pkgx, "one.org", "v1", "lib"),
		filepath.Join(pkgx, "two.org", "v2", "lib"),
	} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "libboth.1.dylib"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := qualifyRef(filepath.Join(prefix, "bin", "tool"), "libboth.1.dylib",
		Options{Prefix: prefix, ZpkgDir: pkgx}); ok {
		t.Errorf("qualifyRef = %q, true — two owners must not be resolved to one", got)
	}
}

// Two versions of one project staged side by side is the ordinary case, not an
// ambiguity: both are the same project, so the closure still answers. Counting
// directories rather than projects would have declined it.
func TestBareReferenceWithTwoVersionsOfOneProject(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "a.org", "v1")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v1.5.5", "v1.5.7"} {
		d := filepath.Join(pkgx, "facebook.com", "zstd", v, "lib")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "libzstd.1.dylib"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := qualifyRef(filepath.Join(prefix, "bin", "tool"), "libzstd.1.dylib",
		Options{Prefix: prefix, ZpkgDir: pkgx})
	want := "@rpath/facebook.com/zstd/v1/lib/libzstd.1.dylib"
	if !ok || got != want {
		t.Errorf("qualifyRef = %q, %v\nwant %q, true — two versions of ONE project are not two owners", got, ok, want)
	}
}

// A soname is put into a glob pattern, so one carrying pattern metacharacters
// makes the search itself fail. It must decline rather than propagate an error
// out of a rewrite that has nothing to do with the caller's request.
func TestBareReferenceWithAPatternInItsName(t *testing.T) {
	pkgx := t.TempDir()
	prefix := filepath.Join(pkgx, "a.org", "v1")
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// filepath.Glob reports a malformed pattern only when it has a name to
	// compare it against: it matches the directories first, then calls Match
	// per entry. An empty lib dir never reaches the comparison, so the error
	// branch needs a directory that matches AND a file inside it.
	lib := filepath.Join(pkgx, "one.org", "v1", "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lib, "libsomething.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := qualifyRef(filepath.Join(prefix, "bin", "tool"), "lib[bad.dylib",
		Options{Prefix: prefix, ZpkgDir: pkgx}); ok {
		t.Errorf("qualifyRef = %q, true — a malformed pattern must decline", got)
	}
}
