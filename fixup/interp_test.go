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

// writeELFInterp crafts a minimal ELF64-LE with a PT_LOAD program header and,
// when slotLen > 0, a PT_INTERP whose string slot is slotLen bytes. Sections
// are omitted: a PT_INTERP is a program header, and a fixture that needed
// sections to be read would be testing the wrong plumbing.
//
// The PT_LOAD is not decoration. Every real ELF has one and PT_INTERP is never
// the only header, so a fixture with one header alone would never make the
// scan skip anything — and the skip is what finds PT_INTERP in a real file.
//
// slotLen 0 writes an ELF with no PT_INTERP at all, which is what nearly every
// file fixup walks looks like.
func writeELFInterp(t *testing.T, path, interp string, slotLen int) {
	t.Helper()
	le := binary.LittleEndian
	const ehsize, phentsize = 64, 56
	phnum := 1
	if slotLen > 0 {
		phnum = 2
	}
	strOff := ehsize + phentsize*phnum
	buf := make([]byte, strOff+slotLen)

	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[32:], uint64(ehsize)) // e_phoff
	le.PutUint16(buf[52:], ehsize)
	le.PutUint16(buf[54:], phentsize)
	le.PutUint16(buf[56:], uint16(phnum))

	phdr := func(i int, typ elf.ProgType, off, size uint64) {
		p := buf[ehsize+phentsize*i:]
		le.PutUint32(p[0:], uint32(typ))
		le.PutUint32(p[4:], uint32(elf.PF_R))
		le.PutUint64(p[8:], off)   // p_offset
		le.PutUint64(p[32:], size) // p_filesz
		le.PutUint64(p[40:], size) // p_memsz
		le.PutUint64(p[48:], 1)    // p_align
	}
	phdr(0, elf.PT_LOAD, 0, uint64(len(buf)))
	if slotLen > 0 {
		phdr(1, elf.PT_INTERP, uint64(strOff), uint64(slotLen))
		copy(buf[strOff:], interp) // NUL-padded by construction
	}

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
	f.Close()
}

func TestReadInterp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "libc.so.6")
	writeELFInterp(t, p, "/opt/pkgx/gnu.org/glibc/v2.44+brewing/lib/ld64.so.1", 64)
	got, err := ReadInterp(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/opt/pkgx/gnu.org/glibc/v2.44+brewing/lib/ld64.so.1"; got != want {
		t.Errorf("ReadInterp = %q, want %q", got, want)
	}

	// No PT_INTERP: "" and no error, because a shared library is the normal
	// case and must not look like a failure.
	q := filepath.Join(dir, "libfoo.so")
	writeELFInterp(t, q, "", 0)
	if got, err := ReadInterp(q); err != nil || got != "" {
		t.Errorf("ReadInterp(no PT_INTERP) = %q, %v; want \"\", nil", got, err)
	}

	if _, err := ReadInterp(filepath.Join(dir, "nope")); err == nil {
		t.Error("ReadInterp of a missing file returned no error")
	}
}

func TestSetInterpShortensInPlaceAndPads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libc.so.6")
	const staged = "/home/linux1/.pkgx/gnu.org/glibc/v2.44+brewing/lib/ld64.so.1"
	writeELFInterp(t, p, staged, len(staged)+1)
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	const want = "/home/linux1/.pkgx/gnu.org/glibc/v2.44/lib/ld64.so.1"
	if err := SetInterp(p, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadInterp(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("ReadInterp = %q, want %q", got, want)
	}
	// In place: the file must not have changed size, or every offset after
	// PT_INTERP would be wrong.
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() {
		t.Errorf("file grew from %d to %d bytes", before.Size(), after.Size())
	}
	// The slack must be NUL, not the tail of the old path: the kernel reads
	// p_filesz bytes and insists the last one is NUL.
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if b[len(b)-1] != 0 {
		t.Errorf("the last byte of the slot is %q, not NUL", b[len(b)-1])
	}
	if strings.Contains(string(b), "+brewing") {
		t.Error("the staging prefix survives in the file's bytes")
	}
}

func TestSetInterpRefusesToGrow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	writeELFInterp(t, p, "/lib/ld.so", 11)
	if err := SetInterp(p, "/a/much/longer/path/ld.so"); !errors.Is(err, ErrInterpNoSpace) {
		t.Errorf("err = %v, want ErrInterpNoSpace", err)
	}
	// And a value that fits EXACTLY, NUL included, is accepted — the boundary
	// is where an off-by-one would corrupt the loader's path.
	if err := SetInterp(p, "/lib/ld2.so"); err == nil {
		t.Error("an 11-byte value in an 11-byte slot left no room for the NUL")
	}
	if err := SetInterp(p, "/lib/ld.s"); err != nil {
		t.Errorf("a value one byte shorter than the slot was refused: %v", err)
	}
}

func TestSetInterpOnAnELFWithout(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libfoo.so")
	writeELFInterp(t, p, "", 0)
	if err := SetInterp(p, "/lib/ld.so"); !errors.Is(err, ErrNoInterp) {
		t.Errorf("err = %v, want ErrNoInterp", err)
	}
	if err := SetInterp(filepath.Join(t.TempDir(), "nope"), "/x"); err == nil {
		t.Error("SetInterp of a missing file returned no error")
	}
}

// The case bk#263 is about: the staging prefix is replaced by the final one,
// and nothing else is touched.
func TestFixInterpUnstagesTheLoaderPath(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "gnu.org", "glibc", "v2.44")
	staging := prefix + "+brewing"

	libc := filepath.Join(prefix, "lib", "libc.so.6")
	writeELFInterp(t, libc, staging+"/lib/glibc-2.44/ld64.so.1", 160)
	// An ordinary executable names the SYSTEM loader, which is not ours to
	// rewrite — the commonest file in bin/ and the one a prefix-blind rewrite
	// would break.
	sys := filepath.Join(prefix, "bin", "gawk")
	writeELFInterp(t, sys, "/lib64/ld-linux-x86-64.so.2", 64)
	// And a library with no PT_INTERP at all.
	lib := filepath.Join(prefix, "lib", "libm.so.6")
	writeELFInterp(t, lib, "", 0)

	var logged []string
	opts := Options{
		Prefix: prefix, BuildInstall: staging, Platform: "linux",
		Log: func(s string) { logged = append(logged, s) },
	}
	if err := fixInterp(opts); err != nil {
		t.Fatal(err)
	}

	got, err := ReadInterp(libc)
	if err != nil {
		t.Fatal(err)
	}
	if want := prefix + "/lib/glibc-2.44/ld64.so.1"; got != want {
		t.Errorf("libc.so.6 interp = %q, want %q", got, want)
	}
	if got, _ := ReadInterp(sys); got != "/lib64/ld-linux-x86-64.so.2" {
		t.Errorf("the system loader was rewritten to %q", got)
	}
	if got, _ := ReadInterp(lib); got != "" {
		t.Errorf("a library without PT_INTERP gained one: %q", got)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "libc.so.6") {
		t.Errorf("logged %v, want one line about libc.so.6", logged)
	}
}

// Nothing to unstage: a mirror path, or a build whose staging prefix IS the
// final one, must not walk the tree at all.
func TestFixInterpWithoutAStagingPrefixDoesNothing(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "v1")
	p := filepath.Join(prefix, "bin", "x")
	writeELFInterp(t, p, "/lib/ld.so", 32)
	for _, o := range []Options{
		{Prefix: prefix, BuildInstall: "", Platform: "linux"},
		{Prefix: prefix, BuildInstall: prefix, Platform: "linux"},
	} {
		if err := fixInterp(o); err != nil {
			t.Fatalf("BuildInstall=%q: %v", o.BuildInstall, err)
		}
	}
	if got, _ := ReadInterp(p); got != "/lib/ld.so" {
		t.Errorf("interp = %q, want it untouched", got)
	}
}

// FixUp must actually call it, and must honour the skip that turns off every
// other patchelf-class rewrite.
func TestFixUpRunsAndSkipsTheInterpRewrite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		skips []string
		want  string
	}{
		{"wired in", nil, "/lib/glibc/ld64.so.1"},
		{"fix-patchelf", []string{"fix-patchelf"}, "+brewing/lib/glibc/ld64.so.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "v2.44")
			staging := prefix + "+brewing"
			libc := filepath.Join(prefix, "lib", "libc.so.6")
			writeELFInterp(t, libc, staging+"/lib/glibc/ld64.so.1", 200)

			if err := FixUp(Options{
				Prefix: prefix, BuildInstall: staging, Platform: "linux", Skips: tc.skips,
			}); err != nil {
				t.Fatal(err)
			}
			got, err := ReadInterp(libc)
			if err != nil {
				t.Fatal(err)
			}
			if want := prefix + strings.TrimPrefix(tc.want, "+brewing"); tc.skips == nil && got != want {
				t.Errorf("interp = %q, want %q", got, want)
			}
			if tc.skips != nil && !strings.Contains(got, "+brewing") {
				t.Errorf("interp = %q, want the staging path left alone", got)
			}
		})
	}
}

// A slot with no terminator is malformed — the kernel refuses such a binary —
// and ReadInterp hands back what is there rather than reading past the
// segment. Reached by a fixture whose p_filesz is exactly the path's length.
func TestReadInterpWithoutATerminator(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	const s = "/lib/ld.so"
	writeELFInterp(t, p, s, len(s))
	if got, err := ReadInterp(p); err != nil || got != s {
		t.Errorf("ReadInterp = %q, %v; want %q, nil", got, err, s)
	}
}

// p_filesz past the end of the file: debug/elf opens it, and the read fails.
// A truncated loader path must surface as an error, not as a short string that
// would then be written back over a good one.
func TestReadInterpShortFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	writeELFInterp(t, p, "/lib/ld.so", 16)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b[:len(b)-8], 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadInterp(p); err == nil {
		t.Error("a PT_INTERP running off the end of the file read without error")
	}
}

// The two os failures SetInterp can meet after a successful elf.Open, reached
// through the seams the rest of the package uses: a test cannot make chmod or
// open fail on demand.
func TestSetInterpOSFailures(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	writeELFInterp(t, p, "/lib/ld.so", 32)

	oldStat := osStat
	osStat = func(string) (os.FileInfo, error) { return nil, errors.New("no stat") }
	err := SetInterp(p, "/lib/l.so")
	osStat = oldStat
	if err == nil || !strings.Contains(err.Error(), "no stat") {
		t.Errorf("err = %v, want the stat failure to surface", err)
	}

	oldOpen := osOpenFile
	osOpenFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("sealed")
	}
	err = SetInterp(p, "/lib/l.so")
	osOpenFile = oldOpen
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Errorf("err = %v, want the open failure to surface", err)
	}
}

// A write that fails mid-walk must stop the build, not be logged and skipped:
// a libc.so.6 left naming a staging directory is the defect this step exists
// to remove.
func TestFixInterpSurfacesAWriteFailure(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "v1")
	staging := prefix + "+brewing"
	libc := filepath.Join(prefix, "lib", "libc.so.6")
	// A slot big enough for the path, and then CHECKED. At 96 bytes this test
	// passed alone and failed in the suite: t.TempDir() is named after the
	// test, so a long name made the staged path longer than the slot, the
	// fixture's string was truncated inside the staging prefix itself, and
	// fixInterp correctly found nothing to do. The test read that silence as
	// "no error" and blamed the code.
	writeELFInterp(t, libc, staging+"/lib/ld.so", 512)
	if cur, err := ReadInterp(libc); err != nil || !strings.HasPrefix(cur, staging) {
		t.Fatalf("fixture: ReadInterp = %q, %v", cur, err)
	}

	old := osOpenFile
	osOpenFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("sealed")
	}
	t.Cleanup(func() { osOpenFile = old })
	err := fixInterp(Options{Prefix: prefix, BuildInstall: staging, Platform: "linux"})
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Errorf("err = %v, want the write failure to stop the walk", err)
	}
}

// FixUp must stop on it, not carry on to the steps after. An artifact whose
// loader path still names a build directory is not one to go on signing.
func TestFixUpStopsWhenTheInterpRewriteFails(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "v2.44")
	staging := prefix + "+brewing"
	libc := filepath.Join(prefix, "lib", "libc.so.6")
	writeELFInterp(t, libc, staging+"/lib/ld.so", 512)

	old := osOpenFile
	osOpenFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("sealed")
	}
	t.Cleanup(func() { osOpenFile = old })
	err := FixUp(Options{Prefix: prefix, BuildInstall: staging, Platform: "linux"})
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Errorf("err = %v, want FixUp to stop on the interp failure", err)
	}
}
