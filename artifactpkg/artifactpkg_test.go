package artifactpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/klauspost/compress/zstd"
)

var errBoom = errors.New("boom")

// errWriter fails every Write, so the eager gzip header write fails.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errBoom }

// fakeWC is an io.WriteCloser with injectable Write/Close failures.
type fakeWC struct {
	writeErr error
	closeErr error
	buf      bytes.Buffer
}

func (f *fakeWC) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.buf.Write(p)
}

func (f *fakeWC) Close() error { return f.closeErr }

const (
	project = "openssl.org"
	version = "1.1.1w"
	prefix  = project + "/v" + version + "/"
)

// makeTree builds an install tree with a hidden file, an executable, a
// nested subdirectory, and a symlink.
func makeTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"bin", "lib/nested"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tool := filepath.Join(dir, "bin", "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tool, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden"), []byte("h"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib", "nested", "data.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../bin/tool", filepath.Join(dir, "lib", "link")); err != nil {
		t.Fatal(err)
	}
	return dir
}

type entry struct {
	hdr  tar.Header
	body []byte
}

// readArtifact decompresses and parses an artifact, preserving entry order.
// readArtifact decodes an artifact with whatever codec Codec currently names, so the
// structural assertions below follow the DEFAULT rather than pinning gzip — a
// default that silently stopped producing a readable tar would go unnoticed
// otherwise.
func readArtifact(t *testing.T, r io.Reader) ([]string, map[string]entry) {
	t.Helper()
	var dec io.Reader
	switch Codec {
	case artifact.ExtTarZst:
		z, err := zstd.NewReader(r)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(z.Close)
		dec = z
	default:
		gz, err := gzip.NewReader(r)
		if err != nil {
			t.Fatal(err)
		}
		dec = gz
	}
	tr := tar.NewReader(dec)
	var order []string
	entries := map[string]entry{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, hdr.Name)
		entries[hdr.Name] = entry{hdr: *hdr, body: body}
	}
	return order, entries
}

func TestArtifactRoundTrip(t *testing.T) {
	dir := makeTree(t)
	var buf bytes.Buffer
	if err := Artifact(dir, project, version, &buf); err != nil {
		t.Fatal(err)
	}
	order, entries := readArtifact(t, &buf)

	want := []string{
		prefix + ".hidden",
		prefix + "bin/",
		prefix + "bin/tool",
		prefix + "lib/",
		prefix + "lib/link",
		prefix + "lib/nested/",
		prefix + "lib/nested/data.txt",
	}
	if len(order) != len(want) {
		t.Fatalf("got %d entries %v, want %d", len(order), order, len(want))
	}
	for i, name := range want {
		if order[i] != name {
			t.Fatalf("entry %d = %q, want %q (order %v)", i, order[i], name, order)
		}
	}
	if !sort.StringsAreSorted(order) {
		t.Fatalf("entries not sorted: %v", order)
	}

	tool := entries[prefix+"bin/tool"]
	if tool.hdr.Typeflag != tar.TypeReg {
		t.Fatalf("bin/tool typeflag = %v, want TypeReg", tool.hdr.Typeflag)
	}
	if m := tool.hdr.FileInfo().Mode().Perm(); m != 0o755 {
		t.Fatalf("bin/tool mode = %o, want 0755", m)
	}
	if string(tool.body) != "#!/bin/sh\necho hi\n" {
		t.Fatalf("bin/tool body = %q", tool.body)
	}

	link := entries[prefix+"lib/link"]
	if link.hdr.Typeflag != tar.TypeSymlink {
		t.Fatalf("lib/link typeflag = %v, want TypeSymlink", link.hdr.Typeflag)
	}
	if link.hdr.Linkname != "../bin/tool" {
		t.Fatalf("lib/link target = %q, want ../bin/tool", link.hdr.Linkname)
	}

	if d := entries[prefix+"bin/"]; d.hdr.Typeflag != tar.TypeDir {
		t.Fatalf("bin/ typeflag = %v, want TypeDir", d.hdr.Typeflag)
	}
	if h := entries[prefix+".hidden"]; string(h.body) != "h" {
		t.Fatalf(".hidden body = %q", h.body)
	}
}

func TestArtifactWalkError(t *testing.T) {
	err := Artifact(filepath.Join(t.TempDir(), "nope"), project, version, &bytes.Buffer{})
	if err == nil {
		t.Fatal("want error for missing installDir")
	}
}

func TestArtifactRelError(t *testing.T) {
	orig := walkDir
	defer func() { walkDir = orig }()
	walkDir = func(root string, fn fs.WalkDirFunc) error {
		return fn("not-absolute", nil, nil)
	}
	if err := Artifact(t.TempDir(), project, version, &bytes.Buffer{}); err == nil {
		t.Fatal("want filepath.Rel error")
	}
}

func TestArtifactLstatError(t *testing.T) {
	orig := osLstat
	defer func() { osLstat = orig }()
	osLstat = func(string) (fs.FileInfo, error) { return nil, errBoom }
	if err := Artifact(makeTree(t), project, version, &bytes.Buffer{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestArtifactReadlinkError(t *testing.T) {
	orig := osReadlink
	defer func() { osReadlink = orig }()
	osReadlink = func(string) (string, error) { return "", errBoom }
	if err := Artifact(makeTree(t), project, version, &bytes.Buffer{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestArtifactFileInfoHeaderError(t *testing.T) {
	orig := tarFileInfoHeader
	defer func() { tarFileInfoHeader = orig }()
	tarFileInfoHeader = func(fs.FileInfo, string) (*tar.Header, error) { return nil, errBoom }
	if err := Artifact(makeTree(t), project, version, &bytes.Buffer{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestArtifactWriteHeaderError(t *testing.T) {
	// Pinned to gzip: it writes its header EAGERLY on the first tar header
	// write, so a failing destination surfaces right there. zstd buffers, so it
	// is simply the wrong instrument for this assertion — the error would show
	// up somewhere else, or not until Close.
	withCodec(t, artifact.ExtTarGz)
	if err := Artifact(makeTree(t), project, version, errWriter{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestArtifactOpenError(t *testing.T) {
	orig := osOpen
	defer func() { osOpen = orig }()
	osOpen = func(string) (*os.File, error) { return nil, errBoom }
	if err := Artifact(makeTree(t), project, version, &bytes.Buffer{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestArtifactCopyError(t *testing.T) {
	orig := ioCopy
	defer func() { ioCopy = orig }()
	ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errBoom }
	if err := Artifact(makeTree(t), project, version, &bytes.Buffer{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestArtifactTarCloseError(t *testing.T) {
	// Pinned to gzip, same reason as TestArtifactWriteHeaderError: an empty tree
	// writes nothing until tw.Close flushes the tar trailer, which triggers the
	// first (failing) write to the destination.
	withCodec(t, artifact.ExtTarGz)
	if err := Artifact(t.TempDir(), project, version, errWriter{}); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteArtifact(t *testing.T) {
	dir := makeTree(t)
	out := t.TempDir()

	p, err := WriteArtifact(dir, project, version, "darwin", "aarch64", out)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(out, project, "darwin", "aarch64", "v"+version+Codec)
	if p != want {
		t.Fatalf("path = %q, want %q", p, want)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	order, _ := readArtifact(t, f)
	if len(order) == 0 || order[0] != prefix+".hidden" {
		t.Fatalf("unexpected artifact contents: %v", order)
	}

	vtxt := filepath.Join(out, project, "darwin", "aarch64", "versions.txt")
	b, err := os.ReadFile(vtxt)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != version+"\n" {
		t.Fatalf("versions.txt = %q, want %q", b, version+"\n")
	}

	// A second call appends.
	if _, err := WriteArtifact(dir, project, "3.0.0", "darwin", "aarch64", out); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(vtxt)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != version+"\n3.0.0\n" {
		t.Fatalf("versions.txt = %q, want %q", b, version+"\n3.0.0\n")
	}
}

func TestWriteArtifactMkdirAllError(t *testing.T) {
	orig := osMkdirAll
	defer func() { osMkdirAll = orig }()
	osMkdirAll = func(string, fs.FileMode) error { return errBoom }
	if _, err := WriteArtifact(makeTree(t), project, version, "darwin", "aarch64", t.TempDir()); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteArtifactCreateError(t *testing.T) {
	orig := osCreate
	defer func() { osCreate = orig }()
	osCreate = func(string) (io.WriteCloser, error) { return nil, errBoom }
	if _, err := WriteArtifact(makeTree(t), project, version, "darwin", "aarch64", t.TempDir()); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteArtifactArtifactError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := WriteArtifact(missing, project, version, "darwin", "aarch64", t.TempDir()); err == nil {
		t.Fatal("want error for missing installDir")
	}
}

func TestWriteArtifactTarballCloseError(t *testing.T) {
	orig := osCreate
	defer func() { osCreate = orig }()
	osCreate = func(string) (io.WriteCloser, error) { return &fakeWC{closeErr: errBoom}, nil }
	if _, err := WriteArtifact(makeTree(t), project, version, "darwin", "aarch64", t.TempDir()); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteArtifactVersionsOpenError(t *testing.T) {
	orig := osOpenFileAppend
	defer func() { osOpenFileAppend = orig }()
	osOpenFileAppend = func(string) (io.WriteCloser, error) { return nil, errBoom }
	if _, err := WriteArtifact(makeTree(t), project, version, "darwin", "aarch64", t.TempDir()); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteArtifactVersionsWriteError(t *testing.T) {
	orig := osOpenFileAppend
	defer func() { osOpenFileAppend = orig }()
	osOpenFileAppend = func(string) (io.WriteCloser, error) { return &fakeWC{writeErr: errBoom}, nil }
	if _, err := WriteArtifact(makeTree(t), project, version, "darwin", "aarch64", t.TempDir()); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

func TestWriteArtifactVersionsCloseError(t *testing.T) {
	orig := osOpenFileAppend
	defer func() { osOpenFileAppend = orig }()
	osOpenFileAppend = func(string) (io.WriteCloser, error) { return &fakeWC{closeErr: errBoom}, nil }
	if _, err := WriteArtifact(makeTree(t), project, version, "darwin", "aarch64", t.TempDir()); !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want errBoom", err)
	}
}

// TestArtifactDoesNotCarryTheBuildersUmask. Two builds of one recipe on two
// machines produced two different artifacts, and the difference was the umask.
// Measured 2026-09-29 on zlib.net 1.3.2, built on the s390x seed VM before and
// after it was replaced: every FILE byte-identical, and every DIRECTORY 0755
// on one host and 0775 on the other — 0022 against 0002.
//
// Files were untouched because cp and install preserve the source's mode; a
// directory gets its mode from mkdir, which applies the umask. So the same
// source, the same compiler and the same libc still gave two digests.
//
// This builds the same tree twice under those two umasks and asserts the tar
// headers come out identical. Without normalise it fails on the directories,
// which is the defect reproduced rather than described.
func TestArtifactDoesNotCarryTheBuildersUmask(t *testing.T) {
	artifactUnder := func(mask int) []string {
		old := syscall.Umask(mask)
		defer syscall.Umask(old)
		dir := t.TempDir()
		// MkdirAll and WriteFile both go through the umask.
		if err := os.MkdirAll(filepath.Join(dir, "lib", "pkgconfig"), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lib", "pkgconfig", "z.pc"), []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lib", "libz.so.1"), []byte("y"), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("libz.so.1", filepath.Join(dir, "lib", "libz.so")); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := Artifact(dir, "zlib.net", "1.3.2", &buf); err != nil {
			t.Fatal(err)
		}
		return headersOf(t, buf.Bytes())
	}

	strict, loose := artifactUnder(0o022), artifactUnder(0o002)
	if len(strict) == 0 {
		t.Fatal("premise: the artifact has no entries")
	}
	if fmt.Sprint(strict) != fmt.Sprint(loose) {
		t.Errorf("the builder's umask reached the artifact:\n  umask 022 %v\n  umask 002 %v", strict, loose)
	}
	// And what it settled on, so a later change has to say so out loud.
	want := []string{
		"lib/ 0755 0:0",
		"lib/libz.so 0755 0:0",
		"lib/libz.so.1 0755 0:0",
		"lib/pkgconfig/ 0755 0:0",
		"lib/pkgconfig/z.pc 0644 0:0",
	}
	if fmt.Sprint(strict) != fmt.Sprint(want) {
		t.Errorf("headers = %v, want %v", strict, want)
	}
}

// An artifact that ships a setuid binary means it, and a=rX would strip the bit.
func TestArtifactKeepsSetuid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ping")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755|os.ModeSetuid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Artifact(dir, "iputils.org", "1.0", &buf); err != nil {
		t.Fatal(err)
	}
	got := headersOf(t, buf.Bytes())
	// 5755: setuid (4000) and sticky (1000) both kept, over a normalised
	// 0755. Written out rather than as a prefix, so a change to either bit
	// has to be stated.
	if len(got) != 1 || got[0] != "ping 5755 0:0" {
		t.Errorf("headers = %v, want [ping 5755 0:0] — both special bits kept", got)
	}
}

// headersOf lists "<name> <mode> <uid>:<gid>" for each entry, with the
// project/version prefix stripped so the assertions read as paths.
func headersOf(t *testing.T, packed []byte) []string {
	t.Helper()
	// Through the same decoder the other structural tests use, so this
	// follows Codec rather than pinning one compressor.
	var dec io.Reader
	switch Codec {
	case artifact.ExtTarZst:
		z, err := zstd.NewReader(bytes.NewReader(packed))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(z.Close)
		dec = z
	default:
		gz, err := gzip.NewReader(bytes.NewReader(packed))
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		dec = gz
	}
	var out []string
	tr := tar.NewReader(dec)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := h.Name
		if i := strings.Index(name, "/v"); i >= 0 {
			if j := strings.Index(name[i+2:], "/"); j >= 0 {
				name = name[i+2+j+1:]
			}
		}
		out = append(out, fmt.Sprintf("%s %04o %d:%d", name, h.Mode, h.Uid, h.Gid))
	}
	sort.Strings(out)
	return out
}
