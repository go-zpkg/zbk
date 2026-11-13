package fixup

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildELF64LE crafts an ELF64-LE with a DT_RUNPATH entry (see buildELFTag).
func buildELF64LE(t *testing.T, runpath, needed string, slotLen int) string {
	return buildELFTag(t, elf.DT_RUNPATH, runpath, needed, slotLen)
}

// buildELFTag crafts a minimal but debug/elf-parseable ELF64 little-endian
// object with .dynstr + .dynamic sections carrying DT_NEEDED and, when
// rpTag != DT_NULL, an rpath-class entry (DT_RUNPATH or DT_RPATH) whose string
// slot is padded to slotLen so SetRunpath has room to rewrite.
func buildELFTag(t *testing.T, rpTag elf.DynTag, runpath, needed string, slotLen int) string {
	t.Helper()
	le := binary.LittleEndian

	// .dynstr: \0 <runpath padded to slotLen> \0 <needed> \0
	pad := runpath + strings.Repeat("\x00", slotLen-len(runpath))
	runpathOff := 1
	neededOff := 1 + len(pad) + 1
	dynstr := append([]byte{0}, pad...)
	dynstr = append(dynstr, 0)
	dynstr = append(dynstr, needed...)
	dynstr = append(dynstr, 0)

	// .dynamic entries: DT_NEEDED, DT_RUNPATH, DT_NULL
	dyn := make([]byte, 0, 48)
	putDyn := func(tag elf.DynTag, val uint64) {
		var e [16]byte
		le.PutUint64(e[0:], uint64(tag))
		le.PutUint64(e[8:], val)
		dyn = append(dyn, e[:]...)
	}
	putDyn(elf.DT_NEEDED, uint64(neededOff))
	if rpTag != elf.DT_NULL {
		putDyn(rpTag, uint64(runpathOff))
	}
	putDyn(elf.DT_NULL, 0)

	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	nameDynstr, nameDynamic, nameShstr := 1, 9, 18

	// file layout
	const ehsize = 64
	off := int64(ehsize)
	align := func(o int64, a int64) int64 {
		if r := o % a; r != 0 {
			return o + (a - r)
		}
		return o
	}
	dynstrOff := off
	off += int64(len(dynstr))
	off = align(off, 8)
	dynamicOff := off
	off += int64(len(dyn))
	shstrOff := off
	off += int64(len(shstr))
	off = align(off, 8)
	shoff := off

	buf := make([]byte, shoff+4*64)
	// ELF header
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(buf[16:], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], uint64(shoff)) // e_shoff
	le.PutUint16(buf[52:], ehsize)        // e_ehsize
	le.PutUint16(buf[58:], 64)            // e_shentsize
	le.PutUint16(buf[60:], 4)             // e_shnum
	le.PutUint16(buf[62:], 3)             // e_shstrndx

	copy(buf[dynstrOff:], dynstr)
	copy(buf[dynamicOff:], dyn)
	copy(buf[shstrOff:], shstr)

	sh := func(idx int, name, typ uint32, off, size uint64, link uint32, entsize uint64) {
		b := buf[shoff+int64(idx)*64:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[24:], off)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], link)
		le.PutUint64(b[48:], 1) // addralign
		le.PutUint64(b[56:], entsize)
	}
	sh(0, 0, uint32(elf.SHT_NULL), 0, 0, 0, 0)
	sh(1, uint32(nameDynstr), uint32(elf.SHT_STRTAB), uint64(dynstrOff), uint64(len(dynstr)), 0, 0)
	sh(2, uint32(nameDynamic), uint32(elf.SHT_DYNAMIC), uint64(dynamicOff), uint64(len(dyn)), 1, 16)
	sh(3, uint32(nameShstr), uint32(elf.SHT_STRTAB), uint64(shstrOff), uint64(len(shstr)), 0, 0)

	p := filepath.Join(t.TempDir(), "obj.so")
	if err := os.WriteFile(p, buf, 0o755); err != nil {
		t.Fatal(err)
	}
	// sanity: debug/elf must accept it
	if f, err := elf.Open(p); err != nil {
		t.Fatalf("crafted ELF invalid: %v", err)
	} else {
		f.Close()
	}
	return p
}

func TestReadRunpathAndNeeded(t *testing.T) {
	p := buildELF64LE(t, "/opt/pkgx/foo/v1/lib", "libc.so.6", 64)
	rp, err := ReadRunpath(p)
	if err != nil || rp != "/opt/pkgx/foo/v1/lib" {
		t.Fatalf("ReadRunpath=%q err=%v", rp, err)
	}
	nd, err := ReadNeeded(p)
	if err != nil || len(nd) != 1 || nd[0] != "libc.so.6" {
		t.Fatalf("ReadNeeded=%v err=%v", nd, err)
	}
	if !isDynamicELF(p) {
		t.Error("isDynamicELF false on a dynamic ELF")
	}
	if isDynamicELF(filepath.Join(t.TempDir(), "nope")) {
		t.Error("isDynamicELF true on missing file")
	}
}

func TestReadRunpathErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "notelf")
	os.WriteFile(bad, []byte("not an elf"), 0o644)
	if _, err := ReadRunpath(bad); err == nil {
		t.Error("expected error on non-ELF")
	}
	if _, err := ReadNeeded(bad); err == nil {
		t.Error("expected error on non-ELF")
	}
	if err := SetRunpath(bad, "x"); err == nil {
		t.Error("expected error on non-ELF")
	}
}

func TestSetRunpathInPlace(t *testing.T) {
	p := buildELF64LE(t, "/very/long/original/placeholder/path/xxxxxxxxxx", "libc.so.6", 80)
	if err := SetRunpath(p, "$ORIGIN/../lib"); err != nil {
		t.Fatal(err)
	}
	got, _ := ReadRunpath(p)
	if got != "$ORIGIN/../lib" {
		t.Fatalf("after set, ReadRunpath=%q", got)
	}
	// NEEDED must be untouched by the string-slot overwrite
	if nd, _ := ReadNeeded(p); len(nd) != 1 || nd[0] != "libc.so.6" {
		t.Errorf("NEEDED corrupted: %v", nd)
	}
}

func TestSetRunpathNoSpace(t *testing.T) {
	p := buildELF64LE(t, "/short", "libc.so.6", 6)
	err := SetRunpath(p, "/a/path/way/too/long/to/fit/in/the/slot")
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("expected ErrNoSpace, got %v", err)
	}
}

func TestRunpathStrOffsetVariants(t *testing.T) {
	// exercise ELFCLASS32 + big-endian + DT_RPATH fallback + none, directly.
	build := func(class elf.Class, order binary.ByteOrder, entries [][2]uint64) []byte {
		var out []byte
		for _, e := range entries {
			if class == elf.ELFCLASS64 {
				var b [16]byte
				order.PutUint64(b[0:], e[0])
				order.PutUint64(b[8:], e[1])
				out = append(out, b[:]...)
			} else {
				var b [8]byte
				order.PutUint32(b[0:], uint32(e[0]))
				order.PutUint32(b[4:], uint32(e[1]))
				out = append(out, b[:]...)
			}
		}
		return out
	}
	rp := uint64(elf.DT_RPATH)
	run := uint64(elf.DT_RUNPATH)
	null := uint64(elf.DT_NULL)

	// RUNPATH wins over a preceding RPATH
	d := build(elf.ELFCLASS64, binary.LittleEndian, [][2]uint64{{rp, 5}, {run, 9}, {null, 0}})
	if off, _, ok := runpathStrOffset(d, elf.ELFCLASS64, binary.LittleEndian); !ok || off != 9 {
		t.Errorf("64LE RUNPATH: %d %v", off, ok)
	}
	// ELFCLASS32 big-endian, only RPATH → fallback at DT_NULL
	d = build(elf.ELFCLASS32, binary.BigEndian, [][2]uint64{{rp, 7}, {null, 0}})
	if off, _, ok := runpathStrOffset(d, elf.ELFCLASS32, binary.BigEndian); !ok || off != 7 {
		t.Errorf("32BE RPATH fallback: %d %v", off, ok)
	}
	// none present
	d = build(elf.ELFCLASS64, binary.LittleEndian, [][2]uint64{{null, 0}})
	if _, _, ok := runpathStrOffset(d, elf.ELFCLASS64, binary.LittleEndian); ok {
		t.Error("expected no offset when none present")
	}
	// RPATH with no DT_NULL terminator → still found at end-of-array
	d = build(elf.ELFCLASS64, binary.LittleEndian, [][2]uint64{{rp, 3}})
	if off, _, ok := runpathStrOffset(d, elf.ELFCLASS64, binary.LittleEndian); !ok || off != 3 {
		t.Errorf("64LE RPATH no-null: %d %v", off, ok)
	}
}

func TestTransformAndOriginRel(t *testing.T) {
	proj := "/opt/pkgx/acme.org/tool"
	if got := transformRpath("$ORIGIN/../lib", proj); got != "$ORIGIN/../lib" {
		t.Errorf("origin passthrough: %q", got)
	}
	if got := transformRpath(proj+"/v1.2.3/lib", proj); got != proj+"/v1.2.3/lib" {
		t.Errorf("own-project passthrough: %q", got)
	}
	if got := transformRpath("/opt/pkgx/dep.org/x/v2.3.4/lib", proj); got != "/opt/pkgx/dep.org/x/v2/lib" {
		t.Errorf("major-versioned: %q", got)
	}
	if got := originRel("$ORIGIN/x", "/a/b"); got != "$ORIGIN/x" {
		t.Errorf("originRel origin passthrough: %q", got)
	}
	if got := originRel("/a/lib", "/a/bin"); got != "$ORIGIN/../lib" {
		t.Errorf("originRel: %q", got)
	}
}

func TestFixRpathsOrchestrator(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "acme.org", "tool", "v1.0.0")
	os.MkdirAll(filepath.Join(prefix, "bin"), 0o755)
	// A crafted ELF whose original RUNPATH exercises all three classes and is
	// long enough to be the in-place rewrite budget:
	//   - "$ORIGIN/keepme"          → kept verbatim
	//   - <prefix>/lib              → into this project → rewritten $ORIGIN-relative
	//   - a long foreign abs path   → dropped (also provides the slot budget)
	initial := "$ORIGIN/keepme:" + prefix + "/lib:/foreign/" + strings.Repeat("x", 140)
	src := buildELF64LE(t, initial, "libc.so.6", len(initial))
	data, _ := os.ReadFile(src)
	exe := filepath.Join(prefix, "bin", "tool")
	os.WriteFile(exe, data, 0o755)
	// a non-ELF (must be skipped, not error) and a header (extension-skipped)
	os.WriteFile(filepath.Join(prefix, "bin", "script"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(prefix, "bin", "x.h"), []byte("h"), 0o644)

	dep := "/opt/pkgx/dep.org/lib/v3.1.0/lib"
	err := FixUp(Options{
		Prefix: prefix, Platform: "linux", DepPaths: []string{dep},
		Log: func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ReadRunpath(exe)
	parts := strings.Split(got, ":")
	if len(parts) != 3 {
		t.Fatalf("expected 3 runpath entries, got %q", got)
	}
	if parts[0] != "$ORIGIN/keepme" {
		t.Errorf("$ORIGIN entry not kept first: %q", got)
	}
	if parts[1] != "$ORIGIN/../lib" {
		t.Errorf("project-dir entry not made $ORIGIN-relative: %q", got)
	}
	// dep is major-versioned (v3.1.0 → v3) then made $ORIGIN-relative to bin/
	if !strings.Contains(parts[2], "/opt/pkgx/dep.org/lib/v3/lib") || !strings.HasPrefix(parts[2], "$ORIGIN/") {
		t.Errorf("dep entry wrong: %q", got)
	}
	if strings.Contains(got, "/foreign/") {
		t.Errorf("foreign abs path should have been dropped: %q", got)
	}
}

func TestFixRpathsAddsOwnLib(t *testing.T) {
	// The package's own lib dir is added $ORIGIN-relative even when the input
	// RUNPATH does not already reference it: a bin/ ELF gets $ORIGIN/../lib and a
	// lib/ ELF gets $ORIGIN/. — so a FROM-scratch artifact finds its sibling libs
	// without LD_LIBRARY_PATH.
	prefix := filepath.Join(t.TempDir(), "acme.org", "tool", "v1.0.0")
	os.MkdirAll(filepath.Join(prefix, "bin"), 0o755)
	os.MkdirAll(filepath.Join(prefix, "lib"), 0o755)
	// An initial RUNPATH that keeps a $ORIGIN entry but does NOT mention …/lib.
	// The in-place rewrite budget is the ORIGINAL string length, so a dropped
	// foreign tail provides room for the (added) own-lib entry.
	initial := "$ORIGIN/keepme:/foreign/" + strings.Repeat("x", 60)
	src := buildELF64LE(t, initial, "libc.so.6", len(initial))
	data, _ := os.ReadFile(src)
	binExe := filepath.Join(prefix, "bin", "tool")
	libExe := filepath.Join(prefix, "lib", "libtool.so.1")
	os.WriteFile(binExe, data, 0o755)
	os.WriteFile(libExe, data, 0o755)

	if err := FixUp(Options{Prefix: prefix, Platform: "linux", Log: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	binRP, _ := ReadRunpath(binExe)
	if binRP != "$ORIGIN/keepme:$ORIGIN/../lib" {
		t.Errorf("bin/ own-lib rpath = %q, want $ORIGIN/keepme:$ORIGIN/../lib", binRP)
	}
	libRP, _ := ReadRunpath(libExe)
	if libRP != "$ORIGIN/keepme:$ORIGIN/." {
		t.Errorf("lib/ own-lib rpath = %q, want $ORIGIN/keepme:$ORIGIN/.", libRP)
	}
}

func TestFixRpathsSkipsAndDarwin(t *testing.T) {
	prefix := t.TempDir()
	os.MkdirAll(filepath.Join(prefix, "bin"), 0o755)
	var logs []string
	log := func(s string) { logs = append(logs, s) }
	// linux skip=fix-patchelf
	if err := FixUp(Options{Prefix: prefix, Platform: "linux", Skips: []string{"fix-patchelf"}, Log: log}); err != nil {
		t.Fatal(err)
	}
	// darwin (walks exes; empty prefix → no-op, no error)
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", Log: log}); err != nil {
		t.Fatal(err)
	}
	// darwin skip=fix-machos
	if err := FixUp(Options{Prefix: prefix, Platform: "darwin", Skips: []string{"fix-machos"}, Log: log}); err != nil {
		t.Fatal(err)
	}
	if !anyContains(logs, "skipping rpath") || !anyContains(logs, "skipping mach-o") {
		t.Errorf("expected skip logs, got %v", logs)
	}
}

// TestRunpathDropsTheStagingPrefix is what published artifacts were carrying: an
// autotools build configured with --prefix=<version>+brewing bakes that path
// into every binary, the entry starts with the project dir so it was kept, and
// $ORIGIN-relativising it preserved a directory that ceases to exist when the
// build is renamed into place.
//
//	$ORIGIN/../../v1.0.0+brewing/lib:$ORIGIN/../lib
//
// Measured before the fix: openucx.org 11 of 13 ELFs, sqlite.org 2 of 2.
func TestRunpathDropsTheStagingPrefix(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "acme.org", "tool", "v1.0.0")
	build := prefix + "+brewing"
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The slot must hold the ORIGINAL string; the rewrite only ever shrinks it,
	// since the final prefix is the staging one minus "+brewing".
	staged := build + "/lib"
	src := buildELF64LE(t, staged, "libc.so.6", len(staged)+16)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(prefix, "bin", "tool")
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := FixUp(Options{Prefix: prefix, BuildInstall: build, Platform: "linux"}); err != nil {
		t.Fatal(err)
	}
	rp, _ := ReadRunpath(exe)
	if strings.Contains(rp, "+brewing") {
		t.Errorf("RUNPATH keeps the staging dir: %q", rp)
	}
	// It is mapped onto the final prefix, not dropped: the build put it there
	// for a reason, and the directory it meant does exist after the rename.
	if !strings.Contains(rp, "$ORIGIN/../lib") {
		t.Errorf("RUNPATH lost the mapped entry: %q", rp)
	}
}

// A staged path is only rewritten when there IS a staging prefix, and a path
// that merely resembles one is left alone.
func TestUnstage(t *testing.T) {
	o := Options{Prefix: "/pkgx/acme.org/v1.0.0", BuildInstall: "/pkgx/acme.org/v1.0.0+brewing"}
	if got := unstage("/pkgx/acme.org/v1.0.0+brewing/lib", o); got != "/pkgx/acme.org/v1.0.0/lib" {
		t.Errorf("unstage = %q", got)
	}
	if got := unstage("/pkgx/acme.org/v1.0.0/lib", o); got != "/pkgx/acme.org/v1.0.0/lib" {
		t.Errorf("an already-final path must pass through, got %q", got)
	}
	if got := unstage("/elsewhere/lib", Options{Prefix: "/p"}); got != "/elsewhere/lib" {
		t.Errorf("no staging prefix configured: %q", got)
	}
}

// Writing a value into a DT_RPATH and leaving the TAG is how this package
// put its own `$ORIGIN/..` into a tag that must not be there:
//
//	$ readelf -d …/gnu.org/glibc/v2.44/lib/glibc-2.44/libc.so.6
//	0x…0f (RPATH)  Library rpath: [$ORIGIN/..]
//	ld.so: elf_get_dynamic_info: Assertion `info[DT_RPATH] == NULL' failed!
//
// glibc's loader refuses a DT_RPATH on what it processes, so a libc artifact
// fixed this way cannot load its own libc — and `ldd` comes from that artifact
// (go-zpkg/bk#256).
func TestSetRunpathModernisesADtRpathTag(t *testing.T) {
	p := buildELFTag(t, elf.DT_RPATH, "/opt/rpath/only", "libc.so.6", 32)

	// Before: a DT_RPATH and no DT_RUNPATH.
	if tags := dynTags(t, p); !tags[elf.DT_RPATH] || tags[elf.DT_RUNPATH] {
		t.Fatalf("fixture is not what the test needs: %v", tags)
	}

	if err := SetRunpath(p, "$ORIGIN/.."); err != nil {
		t.Fatal(err)
	}

	tags := dynTags(t, p)
	if tags[elf.DT_RPATH] {
		t.Error("DT_RPATH survived: glibc's loader aborts on it")
	}
	if !tags[elf.DT_RUNPATH] {
		t.Error("the entry did not become DT_RUNPATH")
	}
	// And the value still reads back, through the tag it now carries.
	got, err := ReadRunpath(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != "$ORIGIN/.." {
		t.Errorf("runpath = %q", got)
	}
}

// A DT_RUNPATH is already right and must not be touched: 295 of the 393
// shared objects measured in the s390x store carry one, and rewriting a tag
// that is already correct is a change nobody asked for.
func TestSetRunpathLeavesADtRunpathTagAlone(t *testing.T) {
	p := buildELF64LE(t, "/opt/longer/old", "libc.so.6", 32)
	if err := SetRunpath(p, "$ORIGIN/.."); err != nil {
		t.Fatal(err)
	}
	tags := dynTags(t, p)
	if tags[elf.DT_RPATH] {
		t.Error("a DT_RPATH appeared from nowhere")
	}
	if !tags[elf.DT_RUNPATH] {
		t.Error("the DT_RUNPATH was lost")
	}
}

// dynTags reports which rpath-class tags an ELF's .dynamic carries.
func dynTags(t *testing.T, path string) map[elf.DynTag]bool {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[elf.DynTag]bool{}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		if v, err := f.DynString(tag); err == nil && len(v) > 0 {
			out[tag] = true
		}
	}
	return out
}
