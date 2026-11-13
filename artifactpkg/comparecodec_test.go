package artifactpkg

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	// ⛔ A DIFFERENT xz PACKAGE, AND ONLY IN THE TEST. go-compressions/xz is a
	// DECODER — it has NewReader and no NewWriter — which is all the reader
	// under test needs. Writing a fixture needs an encoder, so the test takes
	// ulikunitz/xz. Using the same package for both sides would also be the
	// weaker test: a round trip through one implementation cannot tell a
	// correct decoder from one that agrees with its own encoder.
	uxz "github.com/ulikunitz/xz"
)

// ⛔⛔ EVERY CODEC A ARTIFACT IS ACTUALLY PUBLISHED IN. The first reader sniffed
// gzip only, and every unit test passed — because each test wrote its own
// fixture in the codec the reader happened to support. Then `mirror` pulled a
// real one:
//
//	zlib.net/darwin/aarch64/v1.3.2.tar.zst
//
// `Codec` is `artifact.ExtTarZst`. A gzip-only reader could not read a single
// published artifact. These tests exist so the fixtures cannot agree with the
// reader by accident again: each one names the codec it writes.
func writeTar(t *testing.T, path string, wrap func(io.Writer) (io.WriteCloser, error)) string {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var w io.Writer = f
	var closer io.WriteCloser
	if wrap != nil {
		closer, err = wrap(f)
		if err != nil {
			t.Fatal(err)
		}
		w = closer
	}
	tw := tar.NewWriter(w)
	h := reg("p/bin/tool", 0o755)
	h.Size = 3
	if err := tw.WriteHeader(&h); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if closer != nil {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestEveryPublishedCodecIsReadByMagic(t *testing.T) {
	d := t.TempDir()
	// Each is written with a DIFFERENT codec and a name that says nothing
	// about it, so only the magic can be deciding.
	plain := writeTar(t, filepath.Join(d, "a.bin"), nil)
	gz := writeTar(t, filepath.Join(d, "b.bin"), func(w io.Writer) (io.WriteCloser, error) {
		return gzip.NewWriter(w), nil
	})
	zst := writeTar(t, filepath.Join(d, "c.bin"), func(w io.Writer) (io.WriteCloser, error) {
		return zstd.NewWriter(w)
	})
	xzf := writeTar(t, filepath.Join(d, "d.bin"), func(w io.Writer) (io.WriteCloser, error) {
		return uxz.NewWriter(w)
	})

	for _, pair := range [][2]string{{plain, gz}, {plain, zst}, {plain, xzf}, {gz, zst}, {zst, xzf}} {
		rep, err := Compare(pair[0], pair[1])
		if err != nil {
			t.Fatalf("%s vs %s: %v", filepath.Base(pair[0]), filepath.Base(pair[1]), err)
		}
		if !rep.Identical() {
			t.Errorf("%s vs %s: the envelope was read as a difference: %v",
				filepath.Base(pair[0]), filepath.Base(pair[1]), rep.Diffs)
		}
	}
}

// A file whose magic says a codec but whose body is not that codec must be an
// ERROR. Reading it as a plain tar would turn corruption into "no entries",
// and "no entries" into a verdict.
func TestCorruptBodiesUnderEachMagicAreErrors(t *testing.T) {
	d := t.TempDir()
	good := writeTar(t, filepath.Join(d, "good.bin"), func(w io.Writer) (io.WriteCloser, error) {
		return gzip.NewWriter(w), nil
	})
	for name, body := range map[string][]byte{
		"gzip": {0x1f, 0x8b, 'n', 'o', 't', 'g', 'z', 'i', 'p'},
		"zstd": {0x28, 0xb5, 0x2f, 0xfd, 'j', 'u', 'n', 'k'},
		"xz":   {0xfd, '7', 'z', 'X', 'Z', 0x00, 'j', 'u', 'n', 'k'},
	} {
		p := filepath.Join(d, name+".bin")
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Compare(good, p); err == nil {
			t.Errorf("a corrupt %s body compared cleanly", name)
		}
	}
}

// A tar whose last entry is cut short: the header promises bytes the file does
// not have. Hashing the content must fail rather than produce a digest for
// half an entry.
func TestATruncatedArchiveIsAnError(t *testing.T) {
	d := t.TempDir()
	good := writeTar(t, filepath.Join(d, "good.bin"), nil)
	full, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(d, "cut.bin")
	// Keep the header (512 bytes) and one byte of the promised three.
	if err := os.WriteFile(cut, full[:513], 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(good, cut); err == nil {
		t.Error("a truncated archive compared cleanly")
	}
}

// An empty FILE has no magic at all. io.ReadFull returns EOF before it can
// fill the sniff buffer, and that is not a read error — it is an archive with
// nothing in it, which Identical() already refuses to call a pass.
func TestAnEmptyFileIsNoEntriesAndNotAnError(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "empty.bin")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := readEntries(p)
	if err != nil {
		t.Fatalf("an empty file was an error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("an empty file yielded %d entries", len(m))
	}
}

// Diff.String is what a reader actually sees, and the two shapes differ: a
// missing entry has no values to show, everything else has two.
func TestDiffRendersBothShapes(t *testing.T) {
	missing := Diff{Entry: "p/gone", Kind: "only-in-a"}.String()
	if !strings.Contains(missing, "only-in-a") || !strings.Contains(missing, "p/gone") {
		t.Errorf("a missing entry renders as %q", missing)
	}
	if strings.Contains(missing, " vs ") {
		t.Errorf("a missing entry invented two values: %q", missing)
	}
	both := Diff{Entry: "p/x", Kind: "mode", A: "0755", B: "0775"}.String()
	for _, want := range []string{"mode", "p/x", "0755", "vs", "0775"} {
		if !strings.Contains(both, want) {
			t.Errorf("a two-sided difference does not show %q: %q", want, both)
		}
	}
}

// short() is what keeps a digest from filling the line. An empty digest — a
// directory or a symlink, which have no content — must render as something
// rather than as nothing at all.
func TestShortDigestRendering(t *testing.T) {
	if got := short(""); got != "-" {
		t.Errorf("an absent digest renders as %q, want %q", got, "-")
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("a short digest was truncated: %q", got)
	}
	long := "0123456789abcdef0123"
	if got := short(long); got != "0123456789ab" {
		t.Errorf("a long digest renders as %q", got)
	}
}

// A symlink entry: it has a target and no content, so `link` is the field
// that can differ and `content` is the one that cannot.
func TestASymlinkTargetIsCompared(t *testing.T) {
	d := t.TempDir()
	write := func(name, target string) string {
		p := filepath.Join(d, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		h := tar.Header{Name: "p/lib/libz.so", Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777, ModTime: epoch}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		f.Close()
		return p
	}
	a := write("a.bin", "libz.so.1.3.1")
	b := write("b.bin", "libz.so.1.3.2")
	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Classes()["link"] != 1 {
		t.Errorf("a changed symlink target was not reported as link: %v", rep.Diffs)
	}
	if rep.Classes()["content"] != 0 {
		t.Errorf("a symlink was given a content difference: %v", rep.Diffs)
	}
}

// Two entries of the same name but different TYPE — a file replaced by a
// directory — is the kind of change a digest comparison would report as
// "content" and a reader would misread.
func TestATypeChangeIsReportedAsType(t *testing.T) {
	d := t.TempDir()
	a := tarball(t, "a.tar.gz", []tar.Header{reg("p/x", 0o644)}, map[string]string{"p/x": ""})
	_ = a
	b := tarball(t, "b.tar.gz", []tar.Header{dir("p/x", 0o644)}, nil)
	rep, err := Compare(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Classes()["type"] != 1 {
		t.Errorf("a file replaced by a directory was not reported as type: %v", rep.Diffs)
	}
	_ = d
}

// An owner difference. artifactpkg.normalise zeroes uid/gid precisely so this
// cannot happen to an artifact it writes — but an artifact from elsewhere can carry
// them, and silently ignoring the field would hide a real difference.
func TestAnOwnerDifferenceIsReported(t *testing.T) {
	d := t.TempDir()
	write := func(name string, uid, gid int) string {
		p := filepath.Join(d, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		tw := tar.NewWriter(f)
		h := reg("p/x", 0o644)
		h.Uid, h.Gid, h.Size = uid, gid, 1
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
		return p
	}
	rep, err := Compare(write("a.bin", 0, 0), write("b.bin", 1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Classes()["owner"] != 1 {
		t.Errorf("an owner difference was not reported: %v", rep.Diffs)
	}
}
