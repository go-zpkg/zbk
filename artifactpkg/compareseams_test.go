package artifactpkg

import (
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The three error branches in readEntries that a real file cannot reach: a
// freshly opened regular file does not fail its first Read, does not fail
// Seek(0), and zstd.NewReader with no options does not fail at all.
//
// ⛔ INJECTED, NOT DELETED AND NOT EXCUSED. A 100% gate is only worth having
// if it is not worked around, and each of these branches exists for a reason
// a reader should be able to check: an unreadable file must come back as an
// ERROR and never as "no entries", because "no entries" is a verdict.

// failing is a readSeekCloser whose Read or Seek fails on demand.
type failing struct {
	readErr, seekErr error
	inner            io.ReadSeeker
}

func (f *failing) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return f.inner.Read(p)
}
func (f *failing) Seek(off int64, whence int) (int64, error) {
	if f.seekErr != nil {
		return 0, f.seekErr
	}
	return f.inner.Seek(off, whence)
}
func (f *failing) Close() error { return nil }

func TestAFileThatFailsToReadIsAnErrorNotAnEmptyArtifact(t *testing.T) {
	want := errors.New("the disk went away mid-sniff")
	old := openForRead
	openForRead = func(string) (readSeekCloser, error) {
		return &failing{readErr: want, inner: strings.NewReader("")}, nil
	}
	t.Cleanup(func() { openForRead = old })

	if _, err := readEntries("anything"); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v — an unreadable file must not read as an empty artifact", err, want)
	}
}

func TestAFileThatCannotRewindIsAnError(t *testing.T) {
	want := errors.New("cannot seek")
	old := openForRead
	openForRead = func(string) (readSeekCloser, error) {
		return &failing{seekErr: want, inner: strings.NewReader("\x1f\x8bpadding!")}, nil
	}
	t.Cleanup(func() { openForRead = old })

	if _, err := readEntries("anything"); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestAZstdDecoderThatRefusesToStartIsAnError(t *testing.T) {
	want := errors.New("no decoder today")
	old := zstdNewReader
	zstdNewReader = func(io.Reader) (io.Reader, func(), error) { return nil, nil, want }
	t.Cleanup(func() { zstdNewReader = old })

	d := t.TempDir()
	p := filepath.Join(d, "z.bin")
	// Only the magic has to be right — the decoder never gets to the body.
	if err := os.WriteFile(p, []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEntries(p); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// ⛔ AND THE FIRST ARGUMENT IS READ TOO. Compare has one error branch per
// side; a test that only ever corrupts the second one leaves the first
// unexercised, and they are not the same line.
func TestCompareNamesWhichSideCouldNotBeRead(t *testing.T) {
	d := t.TempDir()
	good := writeTar(t, filepath.Join(d, "good.bin"), func(w io.Writer) (io.WriteCloser, error) {
		return gzip.NewWriter(w), nil
	})
	absent := filepath.Join(d, "absent.bin")

	_, err := Compare(absent, good)
	if err == nil {
		t.Fatal("an unreadable FIRST argument compared cleanly")
	}
	if !strings.Contains(err.Error(), "absent.bin") {
		t.Errorf("the error does not say which side failed: %v", err)
	}
	_, err = Compare(good, absent)
	if err == nil {
		t.Fatal("an unreadable SECOND argument compared cleanly")
	}
	if !strings.Contains(err.Error(), "absent.bin") {
		t.Errorf("the error does not say which side failed: %v", err)
	}
}
