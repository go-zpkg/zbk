package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// artifactAt writes a minimal artifact tarball: one directory and one file.
func artifactAt(t *testing.T, path string, dirMode int64, body string, mt time.Time) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	hdrs := []tar.Header{
		{Name: "zlib.net/v1.3.2/lib", Mode: dirMode, Typeflag: tar.TypeDir, ModTime: mt},
		{Name: "zlib.net/v1.3.2/lib/libz.so", Mode: 0o755, Typeflag: tar.TypeReg, ModTime: mt, Size: int64(len(body))},
	}
	for i := range hdrs {
		if err := tw.WriteHeader(&hdrs[i]); err != nil {
			t.Fatal(err)
		}
		if hdrs[i].Typeflag == tar.TypeReg {
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
	return path
}

// artifactVersioned writes an artifact whose paths carry the version, the way a
// real one does: `zlib.net/v<version>/…`.
func artifactVersioned(t *testing.T, path, version string, mt time.Time) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	base := "zlib.net/v" + version
	hdrs := []tar.Header{
		{Name: base + "/lib", Mode: 0o755, Typeflag: tar.TypeDir, ModTime: mt},
		{Name: base + "/lib/libz.so", Mode: 0o755, Typeflag: tar.TypeReg, ModTime: mt, Size: 4},
	}
	for i := range hdrs {
		if err := tw.WriteHeader(&hdrs[i]); err != nil {
			t.Fatal(err)
		}
		if hdrs[i].Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("ELF!")); err != nil {
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
}

// ⛔⛔ THE 2026-09-29 FINDING, END TO END THROUGH THE COMMAND. zlib.net 1.3.2
// built on the s390x seed VM before and after it was replaced: every file
// byte-identical, the directories 0755 and 0775 — the two hosts' umasks.
//
// The exit status must be non-zero and the OUTPUT must name the class, or the
// command is a slower way of comparing two digests.
func TestReproduceNamesTheUmaskClassAndFails(t *testing.T) {
	d := t.TempDir()
	mt := time.Unix(1700000000, 0)
	a := artifactAt(t, filepath.Join(d, "a.tar.gz"), 0o755, "ELF…", mt)
	b := artifactAt(t, filepath.Join(d, "b.tar.gz"), 0o775, "ELF…", mt)

	code, out, _ := run2(t, "reproduce", a, b)
	if code == 0 {
		t.Fatalf("two artifacts differing in directory mode passed:\n%s", out)
	}
	for _, want := range []string{"mode", "zlib.net/v1.3.2/lib", "0755", "0775"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
	// The denominator, so a reader can tell a clean result from an empty one.
	if !strings.Contains(out, "2 entries compared") {
		t.Errorf("the report does not say how much it compared:\n%s", out)
	}
	// And the file must not be implicated — that half is what made the
	// original finding interpretable.
	if strings.Contains(out, "content") {
		t.Errorf("a content difference was reported; every file was identical:\n%s", out)
	}
}

func TestReproducePassesOnTwoIdenticalArtifacts(t *testing.T) {
	d := t.TempDir()
	mt := time.Unix(1700000000, 0)
	a := artifactAt(t, filepath.Join(d, "a.tar.gz"), 0o755, "ELF…", mt)
	b := artifactAt(t, filepath.Join(d, "b.tar.gz"), 0o755, "ELF…", mt)

	code, out, errb := run2(t, "reproduce", a, b)
	if code != 0 {
		t.Fatalf("identical artifacts failed: code=%d\n%s\n%s", code, out, errb)
	}
	if !strings.Contains(out, "bit-identical") {
		t.Errorf("the verdict does not name the question asked:\n%s", out)
	}
}

// ⛔ `-ignore-mtime` ASKS A DIFFERENT QUESTION, IT DOES NOT RELAX THIS ONE.
// artifactpkg deliberately does not fix mtime to an epoch, so two builds an
// hour apart differ by design. The flag must say so in the output, must say
// how many it set aside, and must NOT hide anything else.
func TestIgnoreMTimeIsADifferentQuestionAndHidesNothingElse(t *testing.T) {
	d := t.TempDir()
	mt := time.Unix(1700000000, 0)
	a := artifactAt(t, filepath.Join(d, "a.tar.gz"), 0o755, "ELF…", mt)
	b := artifactAt(t, filepath.Join(d, "b.tar.gz"), 0o755, "ELF…", mt.Add(time.Hour))

	// Without the flag: timestamps are a difference and it fails.
	if code, out, _ := run2(t, "reproduce", a, b); code == 0 {
		t.Errorf("differing timestamps passed as bit-identical:\n%s", out)
	}
	code, out, _ := run2(t, "reproduce", "-ignore-mtime", a, b)
	if code != 0 {
		t.Fatalf("-ignore-mtime did not accept a timestamp-only difference:\n%s", out)
	}
	if !strings.Contains(out, "identical apart from timestamps") {
		t.Errorf("the output does not name the question that was asked:\n%s", out)
	}
	if !strings.Contains(out, "set aside") {
		t.Errorf("the output does not say what it set aside:\n%s", out)
	}

	// And a real difference must still fail UNDER the flag.
	c := artifactAt(t, filepath.Join(d, "c.tar.gz"), 0o775, "ELF…", mt.Add(time.Hour))
	if code, out, _ := run2(t, "reproduce", "-ignore-mtime", a, c); code == 0 {
		t.Errorf("-ignore-mtime hid a mode difference:\n%s", out)
	}
}

// ⛔⛔ AN UNREADABLE ARCHIVE IS NOT A CLEAN RESULT, and neither is an empty
// one. Both are ways for a check to report success having proved nothing —
// the defect a scan that could not read and reported zero is named after.
func TestUnreadableAndEmptyAreNotPasses(t *testing.T) {
	d := t.TempDir()
	good := artifactAt(t, filepath.Join(d, "a.tar.gz"), 0o755, "x", time.Unix(1700000000, 0))

	bad := filepath.Join(d, "bad.tar.gz")
	if err := os.WriteFile(bad, []byte("not an archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run2(t, "reproduce", good, bad); code == 0 {
		t.Errorf("an unreadable archive passed:\n%s", out)
	}
	if code, out, _ := run2(t, "reproduce", good, filepath.Join(d, "absent.tar.gz")); code == 0 {
		t.Errorf("a missing archive passed:\n%s", out)
	}

	// Two empty archives: no differences, and still not a pass.
	empty := func(name string) string {
		p := filepath.Join(d, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		zw := gzip.NewWriter(f)
		tw := tar.NewWriter(zw)
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		return p
	}
	code, out, errb := run2(t, "reproduce", empty("e1.tar.gz"), empty("e2.tar.gz"))
	if code == 0 {
		t.Errorf("two empty archives were certified reproducible:\n%s", out)
	}
	if !strings.Contains(errb, "proves nothing") {
		t.Errorf("the refusal does not say why it proves nothing:\n%s", errb)
	}
}

// ⛔ COMPARING TWO VERSIONS IS NOT AN UNREPRODUCIBLE BUILD, and the report
// that says so is technically true and completely uninformative: an artifact's
// paths carry the version, so `zlib.net/v1.3.1/…` against
// `zlib.net/v1.3.2/…` shares no path at all. Measured on the real published
// artifacts — 14 entries, 28 differences, every one only-in-a or only-in-b.
// Without this the user reads "28 differences" and concludes the factory is
// broken.
func TestComparingTwoVersionsSaysSoRatherThanBlamingTheBuild(t *testing.T) {
	d := t.TempDir()
	mt := time.Unix(1700000000, 0)
	a := filepath.Join(d, "a.tar.gz")
	b := filepath.Join(d, "b.tar.gz")
	artifactVersioned(t, a, "1.3.1", mt)
	artifactVersioned(t, b, "1.3.2", mt)

	code, out, errb := run2(t, "reproduce", "-quiet", a, b)
	if code == 0 {
		t.Fatalf("two different versions were accepted:\n%s", out)
	}
	if !strings.Contains(errb, "share no entry path") {
		t.Errorf("the refusal does not say the paths disagree:\n%s", errb)
	}
	if !strings.Contains(errb, "SAME version") {
		t.Errorf("the refusal does not say what the question actually is:\n%s", errb)
	}
}

// A flag the command does not have is a usage error, not a comparison.
func TestAnUnknownFlagIsAUsageError(t *testing.T) {
	code, _, _ := run2(t, "reproduce", "-no-such-flag", "a", "b")
	if code != 2 {
		t.Errorf("code=%d, want 2", code)
	}
}

func TestReproduceWithoutTwoArgumentsIsAUsageError(t *testing.T) {
	for _, args := range [][]string{{"reproduce"}, {"reproduce", "only-one.tar.gz"}} {
		code, _, errb := run2(t, args...)
		if code != 2 {
			t.Errorf("%v: code=%d, want 2", args, code)
		}
		if !strings.Contains(errb, "usage:") {
			t.Errorf("%v: no usage line:\n%s", args, errb)
		}
	}
}
