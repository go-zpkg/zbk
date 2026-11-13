package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// writeMachOAt builds a Mach-O by hand rather than compiling one, so these
// tests run on every lane: the coverage gate is on linux.
func writeMachOAt(t *testing.T, p string, loads ...string) {
	t.Helper()
	le := binary.LittleEndian
	var body []byte
	for _, s := range loads {
		size := 24 + len(s) + 1
		for size%8 != 0 {
			size++
		}
		cb := make([]byte, size)
		le.PutUint32(cb[0:], 0x0c) // LC_LOAD_DYLIB
		le.PutUint32(cb[4:], uint32(size))
		le.PutUint32(cb[8:], 24)
		copy(cb[24:], s)
		body = append(body, cb...)
	}
	buf := make([]byte, 32+len(body))
	le.PutUint32(buf[0:], 0xfeedfacf)
	le.PutUint32(buf[4:], 0x0100000c)
	le.PutUint32(buf[12:], 6)
	le.PutUint32(buf[16:], uint32(len(loads)))
	le.PutUint32(buf[20:], uint32(len(body)))
	copy(buf[32:], body)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// The question is a stat, not a search: either the store has the file the
// reference names, or the program does not start.
func TestUnresolvedByOwnerIsAStat(t *testing.T) {
	dir := t.TempDir()
	writeMachOAt(t, filepath.Join(dir, "a.org/v1.0.0/lib/liba.1.dylib"))
	writeMachOAt(t, filepath.Join(dir, "top.org/v9.0/bin/tool"),
		"@rpath/a.org/v1.0.0/lib/liba.1.dylib", // present
		"@rpath/gone.org/v2/lib/libgone.2.dylib",
		"/usr/lib/libSystem.B.dylib", // the host's
	)
	got := unresolvedByOwner(dir)
	if len(got["top.org"]) != 1 || got["top.org"][0] != "@rpath/gone.org/v2/lib/libgone.2.dylib" {
		t.Errorf("top.org = %v", got["top.org"])
	}
	// A clean project is still REPORTED as examined, so "ok" means looked at
	// rather than not reached.
	if _, ok := got["a.org"]; !ok {
		t.Error("a clean project was not recorded as examined")
	}
	if len(got["a.org"]) != 0 {
		t.Errorf("a.org = %v, want clean", got["a.org"])
	}
}

// The same reference from forty binaries is forty occurrences of ONE defect.
// Printing all of them buries the count that matters.
func TestUnresolvedByOwnerCountsDistinctReferences(t *testing.T) {
	dir := t.TempDir()
	for _, b := range []string{"one", "two", "three"} {
		writeMachOAt(t, filepath.Join(dir, "x.org/v1/bin/"+b), "@rpath/gone.org/v2/lib/libgone.2.dylib")
	}
	if got := unresolvedByOwner(dir); len(got["x.org"]) != 1 {
		t.Errorf("x.org = %v, want one distinct reference", got["x.org"])
	}
}

// Each project gets its OWN store. A shared one rescues references by
// accident, which is how gpgme's undeclared libgpg-error went unnoticed.
func TestRunUnresolvedGivesEachProjectItsOwnStore(t *testing.T) {
	oldI, oldD, oldS := unresolvedInstall, unresolvedTempDir, unresolvedStdin
	defer func() { unresolvedInstall, unresolvedTempDir, unresolvedStdin = oldI, oldD, oldS }()

	var dirs []string
	base := t.TempDir()
	n := 0
	unresolvedTempDir = func(string, string) (string, error) {
		n++
		d := filepath.Join(base, "store", string(rune('a'+n)))
		dirs = append(dirs, d)
		return d, os.MkdirAll(d, 0o755)
	}
	unresolvedInstall = func(roots map[string]string, dir, _, _ string) ([]artifact.Resolved, error) {
		for p := range roots {
			writeMachOAt(t, filepath.Join(dir, p, "v1/bin/tool"), "@rpath/gone.org/v2/lib/libgone.2.dylib")
		}
		return nil, nil
	}
	unresolvedStdin = strings.NewReader("")

	var out bytes.Buffer
	if rc := runUnresolved([]string{"a.org", "b.org"}, &out, &out); rc != 1 {
		t.Fatalf("rc = %d, want 1 for unresolvable references", rc)
	}
	if len(dirs) != 2 || dirs[0] == dirs[1] {
		t.Errorf("stores = %v, want one per project", dirs)
	}
	if !strings.Contains(out.String(), "2 unresolvable reference(s)") {
		t.Errorf("report:\n%s", out.String())
	}
}

// ⛔ THE PLATFORM REACHES THE INSTALL, or the audit is about the host
// wearing another platform's name. Until artifact v0.55.0 this could only
// ask about the machine it ran on, so the sweep built on it covered
// linux/x86-64 and reported nothing about the other five — which were not
// clean, they were unasked.
func TestRunUnresolvedAuditsTheNamedPlatform(t *testing.T) {
	oldI, oldD, oldS := unresolvedInstall, unresolvedTempDir, unresolvedStdin
	defer func() { unresolvedInstall, unresolvedTempDir, unresolvedStdin = oldI, oldD, oldS }()
	unresolvedTempDir = func(string, string) (string, error) { return t.TempDir(), nil }
	var gotOS, gotArch string
	unresolvedInstall = func(_ map[string]string, _, osn, arch string) ([]artifact.Resolved, error) {
		gotOS, gotArch = osn, arch
		return nil, nil
	}
	unresolvedStdin = strings.NewReader("")

	var out bytes.Buffer
	if rc := runUnresolved([]string{"-platform", "linux/s390x", "a.org"}, &out, &out); rc != 0 {
		t.Fatalf("rc = %d\n%s", rc, out.String())
	}
	if gotOS != "linux" || gotArch != "s390x" {
		t.Errorf("installed for %q/%q, want linux/s390x", gotOS, gotArch)
	}

	// Without the flag it is the host, unchanged — that is what every
	// existing caller relies on.
	wantOS, wantArch := artifact.HostSlug()
	gotOS, gotArch = "", ""
	out.Reset()
	unresolvedStdin = strings.NewReader("")
	if rc := runUnresolved([]string{"a.org"}, &out, &out); rc != 0 {
		t.Fatalf("rc = %d\n%s", rc, out.String())
	}
	if gotOS != wantOS || gotArch != wantArch {
		t.Errorf("default installed for %q/%q, want the host %q/%q", gotOS, gotArch, wantOS, wantArch)
	}
}

// ⛔ A HALF-PARSED PLATFORM IS A CLEAN-LOOKING CATASTROPHE: resolved
// against an empty arch, every artifact is absent, every closure is empty,
// and the audit reports a flawless platform it never installed. Refused
// before anything is fetched.
func TestRunUnresolvedRefusesAMalformedPlatform(t *testing.T) {
	oldI, oldS := unresolvedInstall, unresolvedStdin
	defer func() { unresolvedInstall, unresolvedStdin = oldI, oldS }()
	unresolvedInstall = func(map[string]string, string, string, string) ([]artifact.Resolved, error) {
		t.Error("it installed something despite a malformed platform")
		return nil, nil
	}
	for _, bad := range []string{"linux", "linux/", "/x86-64", "/"} {
		unresolvedStdin = strings.NewReader("")
		var out bytes.Buffer
		if rc := runUnresolved([]string{"-platform", bad, "a.org"}, &out, &out); rc != 2 {
			t.Errorf("-platform %q: rc = %d, want 2\n%s", bad, rc, out.String())
		}
		if !strings.Contains(out.String(), "is not an os/arch") {
			t.Errorf("-platform %q: the refusal does not say what is wrong: %s", bad, out.String())
		}
	}
}

// A clean store is a zero status, and says so.
func TestRunUnresolvedOnACleanStore(t *testing.T) {
	oldI, oldD := unresolvedInstall, unresolvedTempDir
	defer func() { unresolvedInstall, unresolvedTempDir = oldI, oldD }()
	base := t.TempDir()
	unresolvedTempDir = func(string, string) (string, error) { return base, nil }
	unresolvedInstall = func(roots map[string]string, dir, _, _ string) ([]artifact.Resolved, error) {
		writeMachOAt(t, filepath.Join(dir, "a.org/v1/lib/liba.dylib"))
		return nil, nil
	}
	var out bytes.Buffer
	if rc := runUnresolved([]string{"a.org"}, &out, &out); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if !strings.Contains(out.String(), "a.org") || !strings.Contains(out.String(), "0 unresolvable") {
		t.Errorf("report:\n%s", out.String())
	}
}

// An install that fails is reported and the sweep continues: one unreachable
// project must not cost the answer for the rest.
func TestRunUnresolvedKeepsGoingAfterAFailedInstall(t *testing.T) {
	oldI, oldD := unresolvedInstall, unresolvedTempDir
	defer func() { unresolvedInstall, unresolvedTempDir = oldI, oldD }()
	base := t.TempDir()
	k := 0
	unresolvedTempDir = func(string, string) (string, error) {
		k++
		d := filepath.Join(base, string(rune('a'+k)))
		return d, os.MkdirAll(d, 0o755)
	}
	unresolvedInstall = func(roots map[string]string, dir, _, _ string) ([]artifact.Resolved, error) {
		if roots["bad.org"] != "" {
			return nil, errors.New("no such project")
		}
		writeMachOAt(t, filepath.Join(dir, "ok.org/v1/lib/lib.dylib"))
		return nil, nil
	}
	var out, errb bytes.Buffer
	runUnresolved([]string{"bad.org", "ok.org"}, &out, &errb)
	if !strings.Contains(errb.String(), "bad.org") {
		t.Errorf("the failure was not reported: %s", errb.String())
	}
	if !strings.Contains(out.String(), "ok.org") {
		t.Errorf("the sweep stopped at the failure:\n%s", out.String())
	}
}

// Nothing to examine is a usage error, not an empty success.
func TestRunUnresolvedWithNothingToDo(t *testing.T) {
	old := unresolvedStdin
	defer func() { unresolvedStdin = old }()
	unresolvedStdin = strings.NewReader("\n# only a comment\n")
	var out bytes.Buffer
	if rc := runUnresolved(nil, &out, &out); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
}

// Reached through the dispatch, like an operator would.
func TestRunUnresolvedThroughTheDispatch(t *testing.T) {
	oldI := unresolvedInstall
	defer func() { unresolvedInstall = oldI }()
	store := t.TempDir()
	unresolvedInstall = func(roots map[string]string, dir, _, _ string) ([]artifact.Resolved, error) {
		writeMachOAt(t, filepath.Join(dir, "a.org/v1/bin/tool"), "@rpath/gone.org/v2/lib/libgone.2.dylib")
		return nil, nil
	}
	code, out, _ := run2(t, "unresolved", "--store", store, "a.org")
	if code != 1 {
		t.Errorf("exit = %d, want 1 when a reference does not resolve", code)
	}
	if !strings.Contains(out, "libgone.2.dylib") {
		t.Errorf("output:\n%s", out)
	}
}

// --quiet drops the per-reference lines and keeps the counts, for a sweep
// whose output is going to be diffed.
func TestRunUnresolvedQuiet(t *testing.T) {
	oldI := unresolvedInstall
	defer func() { unresolvedInstall = oldI }()
	store := t.TempDir()
	unresolvedInstall = func(roots map[string]string, dir, _, _ string) ([]artifact.Resolved, error) {
		writeMachOAt(t, filepath.Join(dir, "a.org/v1/bin/tool"), "@rpath/gone.org/v2/lib/libgone.2.dylib")
		return nil, nil
	}
	var out bytes.Buffer
	runUnresolved([]string{"--quiet", "--store", store, "a.org"}, &out, &out)
	if strings.Contains(out.String(), "@rpath/gone.org") {
		t.Errorf("--quiet still printed the references:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "1 unresolvable") {
		t.Errorf("--quiet dropped the count too:\n%s", out.String())
	}
}

// A flag it does not know is a usage error, not a sweep of zero projects.
func TestRunUnresolvedWithABadFlag(t *testing.T) {
	var out bytes.Buffer
	if rc := runUnresolved([]string{"--nope"}, &out, &out); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
}

// A list that cannot be READ is not an empty list: saying "no projects" there
// would report a usage mistake for someone else's broken pipe.
func TestRunUnresolvedWhenTheListCannotBeRead(t *testing.T) {
	old := unresolvedStdin
	defer func() { unresolvedStdin = old }()
	unresolvedStdin = errReader{}
	var out bytes.Buffer
	if rc := runUnresolved(nil, &out, &out); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(out.String(), "unresolved:") {
		t.Errorf("the failure was not reported:\n%s", out.String())
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("pipe broke") }

// No store to work in is fatal rather than skipped: every later answer would
// be "nothing found", which reads as success.
func TestRunUnresolvedWhenTheStoreCannotBeMade(t *testing.T) {
	old := unresolvedTempDir
	defer func() { unresolvedTempDir = old }()
	unresolvedTempDir = func(string, string) (string, error) { return "", errors.New("no space") }
	var out bytes.Buffer
	if rc := runUnresolved([]string{"a.org"}, &out, &out); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
}

// A store holds directories and files that are not under any version
// directory. Neither is a reference, and neither is an error.
func TestUnresolvedByOwnerSkipsWhatIsNotAPackagedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a.org/v1/share/doc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not in a package"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := unresolvedByOwner(dir)
	if len(got) != 0 {
		t.Errorf("unresolvedByOwner = %v, want nothing", got)
	}
}

// A store is MOSTLY text, and most of that text sits inside a version
// directory — a man page, a pkg-config file, a header. None of it loads
// anything, and none of it is a finding.
func TestUnresolvedByOwnerSkipsTextInsideAPackage(t *testing.T) {
	dir := t.TempDir()
	writeMachOAt(t, filepath.Join(dir, "a.org/v1/bin/tool"), "@rpath/gone.org/v2/lib/libgone.2.dylib")
	man := filepath.Join(dir, "a.org/v1/share/man/man1/tool.1")
	if err := os.MkdirAll(filepath.Dir(man), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(man, []byte(".TH TOOL 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := unresolvedByOwner(dir)
	if len(got["a.org"]) != 1 {
		t.Errorf("a.org = %v, want only the binary's reference", got["a.org"])
	}
}

// writeELFAt builds a 64-bit dynamic ELF by hand: .dynstr, .dynamic, DT_NEEDED.
// Built rather than compiled so the darwin lane exercises the linux half — the
// lane where no linker would produce one is exactly the lane that used to
// report an ELF store as flawless.
func writeELFAt(t *testing.T, path string, needed ...string) {
	t.Helper()
	le := binary.LittleEndian
	strtab := []byte{0}
	off := func(s string) uint64 {
		o := uint64(len(strtab))
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return o
	}
	var dyn []byte
	ent := func(tag, val uint64) {
		var b [16]byte
		le.PutUint64(b[0:], tag)
		le.PutUint64(b[8:], val)
		dyn = append(dyn, b[:]...)
	}
	for _, n := range needed {
		ent(1, off(n)) // DT_NEEDED
	}
	ent(0, 0) // DT_NULL
	const ehSize, shEntSz, numSec = 64, 64, 4
	shstr := []byte{0}
	nm := func(s string) uint32 {
		o := uint32(len(shstr))
		shstr = append(shstr, s...)
		shstr = append(shstr, 0)
		return o
	}
	nStr, nDyn, nSh := nm(".dynstr"), nm(".dynamic"), nm(".shstrtab")
	dynOff := uint64(ehSize)
	strOff := dynOff + uint64(len(dyn))
	shstrOff := strOff + uint64(len(strtab))
	shOff := shstrOff + uint64(len(shstr))
	buf := make([]byte, shOff+numSec*shEntSz)
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(buf[16:], 3)  // ET_DYN
	le.PutUint16(buf[18:], 62) // EM_X86_64
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], shOff)
	le.PutUint16(buf[52:], ehSize)
	le.PutUint16(buf[58:], shEntSz)
	le.PutUint16(buf[60:], numSec)
	le.PutUint16(buf[62:], 3)
	copy(buf[dynOff:], dyn)
	copy(buf[strOff:], strtab)
	copy(buf[shstrOff:], shstr)
	sh := func(i int, name uint32, typ uint32, off, size, link, entsize uint64) {
		b := buf[shOff+uint64(i)*shEntSz:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], typ)
		le.PutUint64(b[24:], off)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], uint32(link))
		le.PutUint64(b[56:], entsize)
	}
	sh(1, nStr, 3, strOff, uint64(len(strtab)), 0, 0) // SHT_STRTAB
	sh(2, nDyn, 6, dynOff, uint64(len(dyn)), 1, 16)   // SHT_DYNAMIC
	sh(3, nSh, 3, shstrOff, uint64(len(shstr)), 0, 0) // SHT_STRTAB
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// An ELF names a SONAME and the loader searches for it, so the question is
// whether ANYTHING in the closure provides that name — not whether a path
// exists. A provider in a DIFFERENT project satisfies it, which is the whole
// difference from the darwin side.
func TestUnresolvedAnswersForELF(t *testing.T) {
	dir := t.TempDir()
	// The provider, in its own project, under lib/.
	if err := os.MkdirAll(filepath.Join(dir, "zlib.net/v1.3.2/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "zlib.net/v1.3.2/lib/libz.so.1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeELFAt(t, filepath.Join(dir, "top.org/v9.0/bin/tool"),
		"libz.so.1",       // provided, by another project
		"libmissing.so.7", // provided by nothing
		"libc.so.6",       // comes from outside the closure
	)
	got := unresolvedByOwner(dir)
	if len(got["top.org"]) != 1 || got["top.org"][0] != "libmissing.so.7" {
		t.Errorf("top.org = %v, want only libmissing.so.7", got["top.org"])
	}
}

// The regression this closes: a store of ELF files read by a Mach-O-only audit
// came back flawless, because not one file in it could be read. Silence is the
// most expensive answer an audit can give.
func TestAnELFStoreIsNotSilentlyFlawless(t *testing.T) {
	dir := t.TempDir()
	writeELFAt(t, filepath.Join(dir, "a.org/v1/lib/liba.so.1"), "libgone.so.2")
	writeELFAt(t, filepath.Join(dir, "b.org/v2/bin/b"), "libgone.so.2")
	got := unresolvedByOwner(dir)
	if len(got["a.org"]) != 1 || len(got["b.org"]) != 1 {
		t.Fatalf("unresolvedByOwner = %v, want both owners reported", got)
	}
}

// Both formats in one store, which is what a cross-built tree looks like.
func TestUnresolvedReadsBothFormatsInOnePass(t *testing.T) {
	dir := t.TempDir()
	writeMachOAt(t, filepath.Join(dir, "m.org/v1/bin/m"), "@rpath/gone.org/v2/lib/libgone.2.dylib")
	writeELFAt(t, filepath.Join(dir, "e.org/v1/bin/e"), "libgone.so.2")
	got := unresolvedByOwner(dir)
	if len(got["m.org"]) != 1 || len(got["e.org"]) != 1 {
		t.Errorf("unresolvedByOwner = %v", got)
	}
}

// The same soname from two files of one project is one defect, not two — the
// ELF side needs the dedup as much as the Mach-O side does.
func TestELFDedupsPerOwner(t *testing.T) {
	dir := t.TempDir()
	writeELFAt(t, filepath.Join(dir, "x.org/v1/bin/one"), "libgone.so.2")
	writeELFAt(t, filepath.Join(dir, "x.org/v1/bin/two"), "libgone.so.2")
	if got := unresolvedByOwner(dir); len(got["x.org"]) != 1 {
		t.Errorf("x.org = %v, want one distinct soname", got["x.org"])
	}
}

// A store is full of symlinks — every v<major> alias is one, and so is every
// soname beside its versioned file. Following them would count one library
// many times.
func TestUnresolvedSkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeELFAt(t, filepath.Join(dir, "x.org/v1.0.0/lib/libx.so.1.0.0"), "libgone.so.2")
	if err := os.Symlink("libx.so.1.0.0", filepath.Join(dir, "x.org/v1.0.0/lib/libx.so.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("v1.0.0", filepath.Join(dir, "x.org/v1")); err != nil {
		t.Fatal(err)
	}
	if got := unresolvedByOwner(dir); len(got["x.org"]) != 1 {
		t.Errorf("x.org = %v, want the one real file counted once", got["x.org"])
	}
}

// A corner of the store that cannot be read stops that corner, not the sweep.
// An audit that gave up on the first unreadable directory would report the
// projects it did reach as the whole answer.
func TestUnresolvedKeepsWalkingPastAnUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything, so there is nothing to refuse")
	}
	dir := t.TempDir()
	writeELFAt(t, filepath.Join(dir, "good.org/v1/bin/tool"), "libgone.so.2")
	locked := filepath.Join(dir, "locked.org", "v1", "lib")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	got := unresolvedByOwner(dir)
	if len(got["good.org"]) != 1 {
		t.Errorf("the sweep stopped at the unreadable directory: %v", got)
	}
}
