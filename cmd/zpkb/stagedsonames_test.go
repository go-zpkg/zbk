package main

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeELFNeeded crafts a minimal ELF64-LE whose .dynamic names the given
// DT_NEEDED entries, so a tree can be posed with a soname nothing provides.
func writeELFNeeded(t *testing.T, path string, needed ...string) {
	t.Helper()
	le := binary.LittleEndian

	dynstr := []byte{0}
	offs := make([]int, len(needed))
	for i, n := range needed {
		offs[i] = len(dynstr)
		dynstr = append(dynstr, n...)
		dynstr = append(dynstr, 0)
	}
	dyn := make([]byte, 0, 16*(len(needed)+1))
	put := func(tag elf.DynTag, val uint64) {
		var e [16]byte
		le.PutUint64(e[0:], uint64(tag))
		le.PutUint64(e[8:], val)
		dyn = append(dyn, e[:]...)
	}
	for _, o := range offs {
		put(elf.DT_NEEDED, uint64(o))
	}
	put(elf.DT_NULL, 0)

	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	const ehsize = 64
	align := func(o int64) int64 {
		if r := o % 8; r != 0 {
			return o + (8 - r)
		}
		return o
	}
	off := int64(ehsize)
	dynstrOff := off
	off = align(off + int64(len(dynstr)))
	dynamicOff := off
	off += int64(len(dyn))
	shstrOff := off
	off = align(off + int64(len(shstr)))
	shoff := off

	buf := make([]byte, shoff+4*64)
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(buf[16:], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], uint64(shoff))
	le.PutUint16(buf[52:], ehsize)
	le.PutUint16(buf[58:], 64)
	le.PutUint16(buf[60:], 4)
	le.PutUint16(buf[62:], 3)
	copy(buf[dynstrOff:], dynstr)
	copy(buf[dynamicOff:], dyn)
	copy(buf[shstrOff:], shstr)

	sh := func(idx int, name, typ uint32, o, size uint64, link uint32, entsize uint64) {
		b := buf[shoff+int64(idx)*64:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[24:], o)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], link)
		le.PutUint64(b[48:], 1)
		le.PutUint64(b[56:], entsize)
	}
	sh(0, 0, uint32(elf.SHT_NULL), 0, 0, 0, 0)
	sh(1, 1, uint32(elf.SHT_STRTAB), uint64(dynstrOff), uint64(len(dynstr)), 0, 0)
	sh(2, 9, uint32(elf.SHT_DYNAMIC), uint64(dynamicOff), uint64(len(dyn)), 1, 16)
	sh(3, 18, uint32(elf.SHT_STRTAB), uint64(shstrOff), uint64(len(shstr)), 0, 0)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("crafted ELF invalid: %v", err)
	}
	defer f.Close()
	if got, _ := f.DynString(elf.DT_NEEDED); len(got) != len(needed) {
		t.Fatalf("fixture carries %v, want %v", got, needed)
	}
}

// The case that cost two round trips to a runner: a tool needs a library the
// tree does not contain, and says so only when something runs it — deep in a
// build and attributed to whatever ran first.
func TestAuditStagedSonamesNamesWhatIsMissingAndWhoAsks(t *testing.T) {
	dir := t.TempDir()
	writeELFNeeded(t, filepath.Join(dir, "gnu.org/sed/v4.10/bin/sed"), "libc.so.6", "libselinux.so.1")
	writeELFNeeded(t, filepath.Join(dir, "gnu.org/coreutils/v9.12/bin/mkdir"), "libc.so.6", "libselinux.so.1")
	writeELFNeeded(t, filepath.Join(dir, "gnu.org/glibc/v2.44/lib/glibc-2.44/libc.so.6"))

	got := auditStagedSonames(dir)
	for _, w := range []string{"1 soname(s) are NEEDED and provided by nothing here", "libselinux.so.1",
		"gnu.org/coreutils/v9.12/bin/mkdir", "gnu.org/sed/v4.10/bin/sed"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
	// libc.so.6 IS in the tree and must not be reported.
	if strings.Contains(got, "libc.so.6 <-") {
		t.Errorf("a provided soname was reported missing:\n%s", got)
	}
}

// A complete tree says so, and says how many it checked — "nothing missing"
// and "nothing looked at" must not read alike.
func TestAuditStagedSonamesOnACompleteTree(t *testing.T) {
	dir := t.TempDir()
	writeELFNeeded(t, filepath.Join(dir, "p/v1/bin/x"), "libc.so.6")
	writeELFNeeded(t, filepath.Join(dir, "gnu.org/glibc/v2.44/lib/libc.so.6"))
	got := auditStagedSonames(dir)
	if !strings.Contains(got, "every NEEDED soname is provided") || !strings.Contains(got, "1 distinct") {
		t.Errorf("got %q", got)
	}
}

// A SYMLINK is a provider: libz.so -> libz.so.1.3.2 is how most trees name the
// thing a linker asks for, and counting only regular files would report a
// library that is plainly there.
func TestAuditStagedSonamesCountsSymlinks(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "zlib.net/v1/lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	writeELFNeeded(t, filepath.Join(lib, "libz.so.1.3.2"))
	if err := os.Symlink("libz.so.1.3.2", filepath.Join(lib, "libz.so.1")); err != nil {
		t.Fatal(err)
	}
	writeELFNeeded(t, filepath.Join(dir, "p/v1/bin/x"), "libz.so.1")
	if got := auditStagedSonames(dir); !strings.Contains(got, "every NEEDED soname is provided") {
		t.Errorf("a symlinked provider was not counted:\n%s", got)
	}
}

// Many askers: the name is the point, the list is not. Three, then a count.
func TestAuditStagedSonamesCapsTheAskers(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		writeELFNeeded(t, filepath.Join(dir, "p/v1/bin/"+n), "libghost.so.9")
	}
	got := auditStagedSonames(dir)
	if !strings.Contains(got, "(+2 more)") {
		t.Errorf("the asker list was not capped:\n%s", got)
	}
}

// A tree with no ELF at all is not an error and not a silence: it reports
// zero distinct sonames, which is the truth and is distinguishable from a
// walk that could not read anything.
func TestAuditStagedSonamesOnAnEmptyTree(t *testing.T) {
	if got := auditStagedSonames(t.TempDir()); !strings.Contains(got, "(0 distinct)") {
		t.Errorf("got %q", got)
	}
}

// An ELF whose .dynstr DECLARES more bytes than the file holds: debug/elf
// opens it — Open validates headers and does not read section data — and
// DynString fails when it finally does. Truncating the file instead makes
// Open itself refuse, which exercises a different branch; the header is what
// has to lie.
//
// Skipped rather than counted: a census must not stop at one bad file, and
// the tree is the subject here, not the parser.
func TestAuditStagedSonamesSkipsAnUnreadableDynamic(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "p/v1/bin/broken")
	writeELFNeeded(t, bad, "libghost.so.9")
	b, err := os.ReadFile(bad)
	if err != nil {
		t.Fatal(err)
	}
	// Section 1 is .dynstr (see writeELFNeeded). e_shoff is at byte 40, each
	// header is 64 bytes, and sh_size is at offset 32 within one.
	shoff := binary.LittleEndian.Uint64(b[40:])
	binary.LittleEndian.PutUint64(b[shoff+64+32:], uint64(len(b))*16)
	if err := os.WriteFile(bad, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if f, err := elf.Open(bad); err != nil {
		t.Fatalf("the fixture must still OPEN, or it tests the wrong branch: %v", err)
	} else if _, err := f.DynString(elf.DT_NEEDED); err == nil {
		f.Close()
		t.Fatal("the fixture's .dynstr is readable; it tests nothing")
	} else {
		f.Close()
	}

	// A second, intact file so the walk has something to report.
	writeELFNeeded(t, filepath.Join(dir, "p/v1/bin/ok"), "libc.so.6")

	got := auditStagedSonames(dir)
	if strings.Contains(got, "libghost.so.9") {
		t.Errorf("a file whose .dynamic cannot be read was counted:\n%s", got)
	}
	if !strings.Contains(got, "libc.so.6") {
		t.Errorf("the walk stopped at the broken file:\n%s", got)
	}
}
