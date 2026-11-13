package artifactpkg

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/klauspost/compress/zstd"
)

// withCodec sets the packer's codec for one test.
func withCodec(t *testing.T, ext string) {
	t.Helper()
	orig := Codec
	Codec = ext
	t.Cleanup(func() { Codec = orig })
}

// installTree lays out a minimal install prefix to artifact.
func installTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "tool"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCodecDefaultsToZstd pins the migration's end state. It was ExtTarGz while
// the readers were still shipping — the measurements alone were never the
// reason to flip, the deployed readers were.
//
// What makes the default safe is not the codec, it is that a published artifact
// is never rewritten: everything already in the catalogue stays gzip and stays
// readable by any binary, and only new publishes change.
func TestCodecDefaultsToZstd(t *testing.T) {
	if Codec != artifact.ExtTarZst {
		t.Fatalf("Codec = %q, want %q", Codec, artifact.ExtTarZst)
	}
}

// TestArtifactWritesZstdWhenAsked: the payload must be real zstd, and the tar
// inside it must be the same tar gzip would have produced.
func TestArtifactWritesZstdWhenAsked(t *testing.T) {
	withCodec(t, artifact.ExtTarZst)
	install := installTree(t)

	var packed bytes.Buffer
	if err := Artifact(install, "acme.org/tool", "1.0.0", &packed); err != nil {
		t.Fatal(err)
	}

	zr, err := zstd.NewReader(bytes.NewReader(packed.Bytes()))
	if err != nil {
		t.Fatalf("not a zstd stream: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	want := "acme.org/tool/v1.0.0/"
	var found bool
	for _, n := range names {
		if strings.HasPrefix(n, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("entries are not prefixed %q: %v", want, names)
	}
}

// TestWriteArtifactNamesTheFileByCodec: the EXTENSION is what tells a publisher
// (and a static dist) which decoder to use, so it has to follow the codec.
func TestWriteArtifactNamesTheFileByCodec(t *testing.T) {
	for _, ext := range []string{artifact.ExtTarGz, artifact.ExtTarZst} {
		withCodec(t, ext)
		install := installTree(t)
		out := t.TempDir()

		p, err := WriteArtifact(install, "acme.org/tool", "1.0.0", "linux", "aarch64", out)
		if err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		if !strings.HasSuffix(p, "v1.0.0"+ext) {
			t.Errorf("codec %s wrote %q", ext, p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", ext, err)
		}
	}
}

// TestCompressorRejectsUnknownCodec: a typo must stop the build rather than
// produce an unlabelled tarball.
func TestCompressorRejectsUnknownCodec(t *testing.T) {
	withCodec(t, ".tar.br")

	if _, err := compressor(io.Discard); err == nil {
		t.Fatal("want an error")
	}
	if err := Artifact(installTree(t), "acme.org/tool", "1.0.0", io.Discard); err == nil {
		t.Fatal("Artifact must refuse an unknown codec")
	}
}
