package artifactpkg

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tarball writes a .tar.gz from a list of entries and returns its path.
func tarball(t *testing.T, name string, entries []tar.Header, bodies map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, h := range entries {
		hdr := h
		body := bodies[hdr.Name]
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

var epoch = time.Unix(1700000000, 0)

func reg(name string, mode int64) tar.Header {
	return tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeReg, ModTime: epoch}
}
func dir(name string, mode int64) tar.Header {
	return tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeDir, ModTime: epoch}
}

// ⛔⛔ THE DEFECT THIS WHOLE FILE IS THE CONTROL FOR, reproduced from the
// measurement that found it. On 2026-09-29 zlib.net 1.3.2 was built on the
// s390x seed VM before and after it was replaced: every FILE byte-identical,
// and the DIRECTORIES 0755 on one host and 0775 on the other — the two
// umasks, 0022 and 0002.
//
// Two digests would have said "different artifact" and nothing more. The report
// has to name MODE, and name it on the directories, or the next person
// diffs two tarballs by hand as I did.
func TestTheUmaskDefectIsReportedAsModeOnDirectories(t *testing.T) {
	es := []tar.Header{dir("zlib.net/v1.3.2/lib", 0o755), reg("zlib.net/v1.3.2/lib/libz.so", 0o755)}
	bodies := map[string]string{"zlib.net/v1.3.2/lib/libz.so": "ELF…"}
	a := tarball(t, "a.tar.gz", es, bodies)

	es[0].Mode = 0o775 // the other host's umask
	b := tarball(t, "b.tar.gz", es, bodies)

	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Identical() {
		t.Fatal("the two artifacts were called identical; they differ in directory mode")
	}
	if len(rep.Diffs) != 1 {
		t.Fatalf("want exactly one difference, got %v", rep.Diffs)
	}
	d := rep.Diffs[0]
	if d.Kind != "mode" {
		t.Errorf("the difference is reported as %q, not mode: %v", d.Kind, d)
	}
	if d.Entry != "zlib.net/v1.3.2/lib" {
		t.Errorf("the difference is blamed on %q, not the directory", d.Entry)
	}
	if d.A != "0755" || d.B != "0775" {
		t.Errorf("the two modes are not both shown: %v", d)
	}
	// And the FILE is not implicated, which is the half that made the
	// original finding interpretable.
	if n := rep.Classes()["content"]; n != 0 {
		t.Errorf("%d content difference(s) reported; every file was identical", n)
	}
}

// ⛔ TWO DIGESTS SAY "DIFFER". THIS MUST SAY WHICH ENTRY AND HOW — and must
// report EVERY field that differs, not the first. An entry that differs in
// both mode and content has two problems, and a fix for one would leave the
// other unreported.
func TestEveryDifferingFieldIsReportedForOneEntry(t *testing.T) {
	a := tarball(t, "a.tar.gz", []tar.Header{reg("p/bin/tool", 0o755)},
		map[string]string{"p/bin/tool": "one"})
	b := tarball(t, "b.tar.gz", []tar.Header{reg("p/bin/tool", 0o644)},
		map[string]string{"p/bin/tool": "another"})

	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	cls := rep.Classes()
	for _, want := range []string{"mode", "size", "content"} {
		if cls[want] != 1 {
			t.Errorf("%q was not reported once: %v", want, rep.Diffs)
		}
	}
}

func TestAnEntryPresentOnOneSideOnly(t *testing.T) {
	a := tarball(t, "a.tar.gz", []tar.Header{reg("p/a", 0o644), reg("p/b", 0o644)},
		map[string]string{"p/a": "x", "p/b": "y"})
	b := tarball(t, "b.tar.gz", []tar.Header{reg("p/a", 0o644)},
		map[string]string{"p/a": "x"})

	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Diffs) != 1 || rep.Diffs[0].Kind != "only-in-a" || rep.Diffs[0].Entry != "p/b" {
		t.Fatalf("a dropped entry was not named: %v", rep.Diffs)
	}
	// The other direction, which is a different defect: a build that
	// produced something the first did not.
	rep, err = Compare(b, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Diffs) != 1 || rep.Diffs[0].Kind != "only-in-b" {
		t.Fatalf("an added entry was not named: %v", rep.Diffs)
	}
}

// ⛔⛔ AN EMPTY REPORT ON AN EMPTY PAIR IS NOT A PASS. Two archives holding
// nothing produce no differences, and a caller asking "is this reproducible?"
// would be told yes by a check that only counted diffs. The denominator is
// part of the verdict.
func TestNothingComparedIsNotIdentical(t *testing.T) {
	a := tarball(t, "a.tar.gz", nil, nil)
	b := tarball(t, "b.tar.gz", nil, nil)
	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Diffs) != 0 {
		t.Fatalf("empty archives differ? %v", rep.Diffs)
	}
	if rep.Identical() {
		t.Error("two empty archives were certified identical — the comparison proved nothing")
	}
}

// Entry ORDER is not a difference. WriteArtifact sorts, so this is normally
// moot — but a report that depended on order would turn one reordering into
// hundreds of spurious content diffs, burying whatever is really wrong.
func TestOrderIsNotADifference(t *testing.T) {
	bodies := map[string]string{"p/a": "x", "p/b": "y"}
	a := tarball(t, "a.tar.gz", []tar.Header{reg("p/a", 0o644), reg("p/b", 0o644)}, bodies)
	b := tarball(t, "b.tar.gz", []tar.Header{reg("p/b", 0o644), reg("p/a", 0o644)}, bodies)

	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Identical() {
		t.Errorf("reordering was reported as a difference: %v", rep.Diffs)
	}
}

// ⛔ "IDENTICAL APART FROM TIMESTAMPS" IS A DIFFERENT CLAIM FROM BIT-IDENTITY,
// and it is the useful one here: artifactpkg deliberately does NOT fix mtime to
// an epoch, so two builds an hour apart differ by design. WithoutMTime makes
// a caller say which question it is asking instead of relaxing Identical().
func TestTimestampsAreReportedAndCanBeSetAsideSeparately(t *testing.T) {
	es := []tar.Header{reg("p/bin/tool", 0o755)}
	bodies := map[string]string{"p/bin/tool": "same"}
	a := tarball(t, "a.tar.gz", es, bodies)
	es[0].ModTime = epoch.Add(time.Hour)
	b := tarball(t, "b.tar.gz", es, bodies)

	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Identical() {
		t.Error("differing timestamps were not reported at all")
	}
	if rep.Classes()["mtime"] != 1 {
		t.Errorf("the difference is not classed as mtime: %v", rep.Diffs)
	}
	if !rep.WithoutMTime().Identical() {
		t.Errorf("setting timestamps aside did not leave them identical: %v", rep.WithoutMTime().Diffs)
	}
	// And setting timestamps aside must NOT hide anything else.
	es[0].Mode = 0o644
	c := tarball(t, "c.tar.gz", es, bodies)
	rep, err = Compare(a, c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.WithoutMTime().Identical() {
		t.Error("a mode difference survived WithoutMTime as identical")
	}
}

// A plain .tar and a .tar.gz of the same content are the same artifact: a
// caller comparing a rebuild against something already unpacked should not be
// told they differ because of the envelope.
func TestGzipIsSniffedNotAssumedFromTheName(t *testing.T) {
	bodies := map[string]string{"p/a": "x"}
	gz := tarball(t, "a.tar.gz", []tar.Header{reg("p/a", 0o644)}, bodies)

	plain := filepath.Join(t.TempDir(), "b.tar.gz") // named .gz, NOT gzipped
	f, err := os.Create(plain)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	h := reg("p/a", 0o644)
	h.Size = 1
	if err := tw.WriteHeader(&h); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rep, err := Compare(gz, plain)
	if err != nil {
		t.Fatalf("a .tar named .tar.gz was not read: %v", err)
	}
	if !rep.Identical() {
		t.Errorf("the envelope was reported as a difference: %v", rep.Diffs)
	}
}

// An unreadable archive is an ERROR, never an empty report. "Could not read"
// and "no differences" must not arrive at a caller looking the same.
func TestAnUnreadableArchiveIsAnError(t *testing.T) {
	good := tarball(t, "a.tar.gz", []tar.Header{reg("p/a", 0o644)}, map[string]string{"p/a": "x"})
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	if err := os.WriteFile(bad, []byte("not an archive at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(good, bad); err == nil {
		t.Error("an unreadable archive compared cleanly")
	}
	if _, err := Compare(good, filepath.Join(t.TempDir(), "absent.tar.gz")); err == nil {
		t.Error("a missing archive compared cleanly")
	}
}
