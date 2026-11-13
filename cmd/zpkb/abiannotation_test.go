package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/go-zpkg/artifact"
)

// An artifact is mostly not shared libraries, and none of the rest is an ABI
// anybody binds to.
func TestSonamesFromTarballIgnoresNonLibraries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range map[string][]byte{
		"bin/hello":       []byte("#!/bin/sh\necho hi\n"),
		"lib/libz.a":      []byte("!<arch>\n"),
		"share/doc/READ":  []byte("hello"),
		"lib/pkgconfig/z": []byte("Name: z\n"),
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(data)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink IS a soname in most layouts (libz.1.dylib -> libz.1.3.2.dylib).
	// Counting it would report the same ABI twice, once per name.
	if err := tw.WriteHeader(&tar.Header{Name: "lib/libz.dylib", Typeflag: tar.TypeSymlink, Linkname: "libz.1.3.2.dylib", Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tb := gzBytes(buf.Bytes())
	got, err := sonamesFromTarball(tb, artifact.ExtTarGz)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("sonames = %v, want none", got)
	}
}

// The xz branch reads the same way.
func TestSonamesFromTarballXZ(t *testing.T) {
	tb := xzBytes(t, tarBytes(map[string][]byte{"bin/x": []byte("#!/bin/sh\n")}))
	got, err := sonamesFromTarball(tb, artifact.ExtTarXz)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("sonames = %v, want none", got)
	}
}

// A stream that is not an artifact is an error, not an empty answer: the caller
// logs it and publishes anyway, and the two must not look alike.
func TestSonamesFromTarballOnGarbage(t *testing.T) {
	if _, err := sonamesFromTarball([]byte("not a gzip"), artifact.ExtTarGz); err == nil {
		t.Error("garbage gzip read as empty")
	}
	if _, err := sonamesFromTarball([]byte("not an xz"), artifact.ExtTarXz); err == nil {
		t.Error("garbage xz read as empty")
	}
	// A valid gzip whose contents are not a tar.
	if _, err := sonamesFromTarball(gzBytes([]byte("still not a tar")), artifact.ExtTarGz); err == nil {
		t.Error("garbage tar read as empty")
	}
}

// The annotation key is namespaced like the others this factory writes.
func TestABIProvidesAnnotationKey(t *testing.T) {
	if !strings.HasPrefix(ABIProvidesAnnotation, "org.go-zpkg.") {
		t.Errorf("annotation key %q is not in our namespace", ABIProvidesAnnotation)
	}
}

// The answer, on an artifact that really contains a shared library.
//
// testdata/libfoo.so.1 is a minimal ELF64 whose DT_SONAME is "libfoo.so.1",
// generated once by fixup's own ELF builder so this package needs no second
// copy of it.
func TestSonamesFromTarballReadsALibrary(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join("testdata", "libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	tb := gzBytes(tarBytes(map[string][]byte{
		"lib/libfoo.so.1": lib,
		"bin/foo":         []byte("#!/bin/sh\n"),
	}))
	got, err := sonamesFromTarball(tb, artifact.ExtTarGz)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "libfoo.so.1" {
		t.Fatalf("sonames = %v, want [libfoo.so.1]", got)
	}
}

// A tar cut off inside an entry is an error, not a short answer. The header
// reads, the body does not, and returning what was found so far would describe
// an artifact by the part of it that happened to arrive.
func TestSonamesFromTarballOnATruncatedEntry(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join("testdata", "libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	full := tarBytes(map[string][]byte{"lib/libfoo.so.1": lib})
	// Keep the 512-byte header and half the body.
	cut := full[:512+len(lib)/2]
	if _, err := sonamesFromTarball(gzBytes(cut), artifact.ExtTarGz); err == nil {
		t.Error("a truncated entry read as a complete artifact")
	}
}

// The whole point, end to end: an artifact that ships a shared library is
// published with an annotation saying which ABI it provides.
func TestPublishArtifactAnnotatesTheABIItProvides(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join("testdata", "libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	oldPush := ociPush
	ociPush = func(_, _, _, _, _ string, _ []byte, _ string, _ []artifact.Referrer, ann map[string]string) (ocispec.Descriptor, error) {
		got = ann
		return ocispec.Descriptor{}, nil
	}
	defer func() { ociPush = oldPush }()

	p := filepath.Join(t.TempDir(), "v1.0.0"+artifact.ExtTarGz)
	if err := os.WriteFile(p, gzBytes(tarBytes(map[string][]byte{"lib/libfoo.so.1": lib})), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := publishArtifact(publishOptions{
		Dist: "oci://example.invalid/x", Project: "acme.org/tool", Version: "1.0.0",
		OS: "linux", Arch: "aarch64", Path: p,
	}); err != nil {
		t.Fatal(err)
	}
	if got[ABIProvidesAnnotation] != "libfoo.so.1" {
		t.Errorf("annotation = %q, want libfoo.so.1 (all: %v)", got[ABIProvidesAnnotation], got)
	}
}

// zstd is what this factory publishes by DEFAULT, and the first version of
// this reader knew only gzip and xz. It failed on every real artifact —
//
//	bk: could not read the sonames of fftw.org 3.3.11: gzip: invalid header
//
// — so the annotation was written on nothing at all. This is the case that was
// missing.
func TestSonamesFromTarballReadsAZstdArtifact(t *testing.T) {
	lib, err := os.ReadFile(filepath.Join("testdata", "libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBytes(map[string][]byte{"lib/libfoo.so.1": lib})); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := sonamesFromTarball(buf.Bytes(), artifact.ExtTarZst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "libfoo.so.1" {
		t.Fatalf("sonames = %v, want [libfoo.so.1]", got)
	}
}
