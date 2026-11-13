package fetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-zpkg/artifact"
	"github.com/ulikunitz/xz"
)

// restoreSeams resets every injectable seam after the test.
func restoreSeams(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		httpGet = getWithAgent
		gitPlainClone = gogit.PlainClone
		osRemoveAll = os.RemoveAll
		osMkdirAll = os.MkdirAll
		osOpen = os.Open
		osOpenHash = os.Open
		osSymlink = os.Symlink
		osOpenFile = os.OpenFile
		ioCopy = io.Copy
		ioCopyHash = io.Copy
		zipOpen = defaultZipOpen
		osChtimes = os.Chtimes
	})
}

// serve starts a test server that answers every request with body.
func serve(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

type tarEntry struct {
	name string
	typ  byte
	mode int64
	body string
	link string
	mod  time.Time
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, ModTime: e.mod}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", e.name, err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("Write(%q): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func gzWrap(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func xzWrap(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := xw.Write(data); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := xw.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return buf.Bytes()
}

type zipEntry struct {
	name    string
	mode    fs.FileMode // 0 means "leave unset" (no Unix mode bits)
	body    string
	symlink bool
	mod     time.Time
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: e.mod}
		if e.symlink {
			hdr.SetMode(e.mode.Perm() | fs.ModeSymlink)
		} else if e.mode != 0 {
			if strings.HasSuffix(e.name, "/") {
				hdr.SetMode(e.mode.Perm() | fs.ModeDir)
			} else {
				hdr.SetMode(e.mode.Perm())
			}
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("CreateHeader(%q): %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("zip write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// bz2TarHex is a bzip2-compressed tar holding "bz/" (0755) and
// "bz/hello.txt" (0644, "hello bz2\n"). compress/bzip2 has no writer, so
// the fixture is pre-generated (python3 tarfile w:bz2) and embedded.
const bz2TarHex = "425a6839314159265359dad7470f00008afb80ca9001004001ff80040272449e50080820007412921a1a0d01881a3209293268d00001a03eea8baa4e48083d2421ce897b6014dcc1e4c210c01b228923359ba841628107c29107546d752caad6aae5b610b2f11c3e6c8947113d08922733e918cd321103f177245385090dad7470f0"

func bz2Tar(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(bz2TarHex)
	if err != nil {
		t.Fatalf("decode bz2 fixture: %v", err)
	}
	return data
}

// sampleTar is a representative source tree: a dir, a regular file, an
// executable, a symlink, a fifo (skipped) and a "./" entry (skipped).
func sampleTar(t *testing.T) []byte {
	return buildTar(t, []tarEntry{
		{name: "./", typ: tar.TypeDir, mode: 0o755},
		{name: "src/", typ: tar.TypeDir, mode: 0o755},
		{name: "src/main.c", typ: tar.TypeReg, mode: 0o644, body: "int main(){}\n"},
		{name: "configure", typ: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\n"},
		{name: "src/link.c", typ: tar.TypeSymlink, mode: 0o777, link: "main.c"},
		{name: "src/fifo", typ: tar.TypeFifo, mode: 0o644},
	})
}

func checkSampleTree(t *testing.T, dir string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, "src", "main.c"))
	if err != nil || string(got) != "int main(){}\n" {
		t.Fatalf("main.c = %q, %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "src", "main.c"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("main.c mode = %v, %v; want 0644", fi.Mode(), err)
	}
	fi, err = os.Stat(filepath.Join(dir, "configure"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("configure mode = %v, %v; want 0755", fi.Mode(), err)
	}
	fi, err = os.Stat(filepath.Join(dir, "src"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("src dir = %v, %v; want dir 0755", fi.Mode(), err)
	}
	link, err := os.Readlink(filepath.Join(dir, "src", "link.c"))
	if err != nil || link != "main.c" {
		t.Fatalf("link.c -> %q, %v; want main.c", link, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "src", "fifo")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fifo should be skipped, Lstat err = %v", err)
	}
}

func TestFetchTarGz(t *testing.T) {
	s := serve(t, gzWrap(t, sampleTar(t)))
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tar.gz", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkSampleTree(t, dir)
}

func TestFetchTgzWithQueryString(t *testing.T) {
	s := serve(t, gzWrap(t, sampleTar(t)))
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tgz?token=abc#frag", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkSampleTree(t, dir)
}

func TestFetchTarXz(t *testing.T) {
	s := serve(t, xzWrap(t, sampleTar(t)))
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tar.xz", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkSampleTree(t, dir)
}

func TestFetchTarPlain(t *testing.T) {
	s := serve(t, sampleTar(t))
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tar", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkSampleTree(t, dir)
}

func TestFetchTarBz2(t *testing.T) {
	for _, ext := range []string{".tar.bz2", ".tbz2"} {
		s := serve(t, bz2Tar(t))
		dir := t.TempDir()
		if _, err := Fetch(s.URL+"/pkg"+ext, dir, 0); err != nil {
			t.Fatalf("Fetch(%s): %v", ext, err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "bz", "hello.txt"))
		if err != nil || string(got) != "hello bz2\n" {
			t.Fatalf("hello.txt = %q, %v", got, err)
		}
	}
}

func TestFetchStripComponents(t *testing.T) {
	data := gzWrap(t, buildTar(t, []tarEntry{
		{name: "pkg-1.0/", typ: tar.TypeDir, mode: 0o755},
		{name: "pkg-1.0/src/", typ: tar.TypeDir, mode: 0o755},
		{name: "pkg-1.0/src/main.c", typ: tar.TypeReg, mode: 0o644, body: "x\n"},
	}))
	s := serve(t, data)
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg-1.0.tar.gz", dir, 1); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "src", "main.c")); err != nil || string(got) != "x\n" {
		t.Fatalf("src/main.c = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pkg-1.0")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("pkg-1.0 should be stripped, err = %v", err)
	}
}

func TestFetchZip(t *testing.T) {
	data := buildZip(t, []zipEntry{
		{name: "pkg/", mode: 0o755},
		{name: "pkg/nomode/"}, // no Unix mode bits: permOr fallback
		{name: "pkg/readme.txt", mode: 0o644, body: "zip body\n"},
		{name: "pkg/run", mode: 0o755, body: "#!/bin/sh\n"},
		{name: "pkg/alias.txt", mode: 0o777, symlink: true, body: "readme.txt"},
	})
	s := serve(t, data)
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.zip", dir, 1); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "readme.txt")); err != nil || string(got) != "zip body\n" {
		t.Fatalf("readme.txt = %q, %v", got, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "run"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("run mode = %v, %v; want 0755", fi.Mode(), err)
	}
	// Entries without Unix mode bits get MS-DOS-derived perms from
	// archive/zip; the perm-0 fallback itself is covered by
	// TestFetchTarZeroModeFallbacks.
	fi, err = os.Stat(filepath.Join(dir, "nomode"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("nomode = %v, %v; want dir", fi, err)
	}
	link, err := os.Readlink(filepath.Join(dir, "alias.txt"))
	if err != nil || link != "readme.txt" {
		t.Fatalf("alias.txt -> %q, %v; want readme.txt", link, err)
	}
}

func TestFetchUnknownExtension(t *testing.T) {
	_, err := Fetch("http://example.invalid/pkg.rar", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "unknown archive extension") {
		t.Fatalf("err = %v; want unknown archive extension", err)
	}
}

func TestFetchHTTPGetError(t *testing.T) {
	_, err := Fetch("http://127.0.0.1:1/pkg.tar", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "fetch: GET") {
		t.Fatalf("err = %v; want GET error", err)
	}
}

func TestFetchHTTPStatusNotOK(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(http.NotFound))
	t.Cleanup(s.Close)
	_, err := Fetch(s.URL+"/pkg.tar", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v; want 404", err)
	}
}

func TestFetchDestDirCreateError(t *testing.T) {
	s := serve(t, sampleTar(t))
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Fetch(s.URL+"/pkg.tar", filepath.Join(blocker, "dest"), 0)
	if err == nil || !strings.Contains(err.Error(), "fetch: create") {
		t.Fatalf("err = %v; want create error", err)
	}
}

func TestFetchBadGzip(t *testing.T) {
	s := serve(t, []byte("not gzip"))
	_, err := Fetch(s.URL+"/pkg.tar.gz", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "read gzip") {
		t.Fatalf("err = %v; want read gzip error", err)
	}
}

func TestFetchBadXz(t *testing.T) {
	s := serve(t, []byte("not xz at all"))
	_, err := Fetch(s.URL+"/pkg.tar.xz", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "read xz") {
		t.Fatalf("err = %v; want read xz error", err)
	}
}

func TestFetchBadZip(t *testing.T) {
	s := serve(t, []byte("not a zip"))
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "read zip") {
		t.Fatalf("err = %v; want read zip error", err)
	}
}

func TestFetchMalformedTar(t *testing.T) {
	s := serve(t, bytes.Repeat([]byte{'x'}, 1024))
	_, err := Fetch(s.URL+"/pkg.tar", t.TempDir(), 0)
	// Tar extraction delegates to artifact.Extract, which surfaces the underlying
	// archive/tar error directly ("invalid tar header").
	if err == nil || !strings.Contains(err.Error(), "tar header") {
		t.Fatalf("err = %v; want a malformed-tar error", err)
	}
}

func TestFetchZipBodyReadError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("short"))
	}))
	t.Cleanup(s.Close)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	// A server that keeps sending less than it announced is now reported as what
	// it is, with the byte counts, once the resume attempts are exhausted —
	// instead of an "unexpected EOF" from whichever decoder happened to be
	// reading, which is how kernel.org/linux's 150 MB tarball failed.
	if err == nil || !strings.Contains(err.Error(), "still truncated after") {
		t.Fatalf("err = %v; want the truncation reported with its counts", err)
	}
}

// TestFetchResumesATruncatedBody: the point of the whole exercise. The server
// cuts the first response short and honours the Range request that follows, so
// the fetch completes instead of failing.
func TestFetchResumesATruncatedBody(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(buildTar(t, []tarEntry{{name: "pkg/hello.txt", typ: tar.TypeReg, mode: 0o644, body: "bonjour"}}))
	_ = zw.Close()
	full := gz.Bytes()
	cut := len(full) / 2
	var served int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		if rng := r.Header.Get("Range"); rng != "" {
			var off int
			_, _ = fmt.Sscanf(rng, "bytes=%d-", &off)
			w.Header().Set("Content-Length", strconv.Itoa(len(full)-off))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(full[off:])
			return
		}
		// First response: announce everything, deliver half, then hang up.
		w.Header().Set("Content-Length", strconv.Itoa(len(full)))
		_, _ = w.Write(full[:cut])
	}))
	t.Cleanup(s.Close)

	dest := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tar.gz", dest, 1); err != nil {
		t.Fatalf("a resumable truncation must not fail the fetch: %v", err)
	}
	if served < 2 {
		t.Errorf("served %d response(s); the resume request never happened", served)
	}
	b, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil || string(b) != "bonjour" {
		t.Errorf("extracted %q err=%v, want the complete archive", b, err)
	}
}

func TestFetchTarPathTraversal(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{name: "../evil.txt", typ: tar.TypeReg, mode: 0o644, body: "evil"},
	})
	s := serve(t, data)
	dir := t.TempDir()
	_, err := Fetch(s.URL+"/pkg.tar", dir, 0)
	if !errors.Is(err, artifact.ErrInsecurePath) {
		t.Fatalf("err = %v; want artifact.ErrInsecurePath", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("evil.txt escaped destDir, err = %v", err)
	}
}

func TestFetchTarAbsolutePath(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{name: "/abs.txt", typ: tar.TypeReg, mode: 0o644, body: "evil"},
	})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.tar", t.TempDir(), 0)
	if !errors.Is(err, artifact.ErrInsecurePath) {
		t.Fatalf("err = %v; want artifact.ErrInsecurePath", err)
	}
}

func TestFetchZipAbsolutePath(t *testing.T) {
	// The zip extractor keeps bk's own safeTarget; an absolute entry name is
	// rejected with the "absolute path" diagnostic (tar now delegates to
	// artifact.Extract, so this is the case that still exercises that branch).
	data := buildZip(t, []zipEntry{
		{name: "/abs.txt", mode: 0o644, body: "evil"},
	})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("err = %v; want absolute path", err)
	}
}

func TestFetchZipPathTraversal(t *testing.T) {
	data := buildZip(t, []zipEntry{
		{name: "../evil.txt", mode: 0o644, body: "evil"},
	})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("err = %v; want path traversal", err)
	}
}

// failMkdirOn returns an osMkdirAll that fails for paths containing marker.
func failMkdirOn(marker string) func(string, fs.FileMode) error {
	return func(p string, m fs.FileMode) error {
		if strings.Contains(p, marker) {
			return errors.New("mkdir boom")
		}
		return os.MkdirAll(p, m)
	}
}

// Tar extraction now delegates to artifact.Extract; its mkdir / symlink /
// open-file / copy error branches live in and are covered by the artifact
// package. The zip extractor keeps bk's own inline logic, so the Zip* seam
// tests below continue to exercise those bk seams.

func TestFetchZipMkdirErrors(t *testing.T) {
	cases := []struct {
		name    string
		entries []zipEntry
	}{
		{"dir entry", []zipEntry{{name: "boomdir/", mode: 0o755}}},
		{"symlink parent", []zipEntry{{name: "boomdir/l", mode: 0o777, symlink: true, body: "x"}}},
		{"file parent", []zipEntry{{name: "boomdir/f", mode: 0o644, body: "x"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restoreSeams(t)
			osMkdirAll = failMkdirOn("boomdir")
			s := serve(t, buildZip(t, tc.entries))
			_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
			if err == nil || !strings.Contains(err.Error(), "mkdir boom") {
				t.Fatalf("err = %v; want mkdir boom", err)
			}
		})
	}
}

func TestFetchZipSymlinkError(t *testing.T) {
	restoreSeams(t)
	osSymlink = func(_, _ string) error { return errors.New("symlink boom") }
	data := buildZip(t, []zipEntry{{name: "l", mode: 0o777, symlink: true, body: "x"}})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "symlink boom") {
		t.Fatalf("err = %v; want symlink boom", err)
	}
}

func TestFetchZipOpenFileError(t *testing.T) {
	restoreSeams(t)
	osOpenFile = func(string, int, fs.FileMode) (*os.File, error) { return nil, errors.New("open boom") }
	data := buildZip(t, []zipEntry{{name: "f", mode: 0o644, body: "x"}})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "open boom") {
		t.Fatalf("err = %v; want open boom", err)
	}
}

func TestFetchZipSymlinkCopyError(t *testing.T) {
	restoreSeams(t)
	ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("copy boom") }
	data := buildZip(t, []zipEntry{{name: "l", mode: 0o777, symlink: true, body: "x"}})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "copy boom") {
		t.Fatalf("err = %v; want copy boom", err)
	}
}

func TestFetchZipEntryOpenErrors(t *testing.T) {
	cases := []struct {
		name    string
		entries []zipEntry
	}{
		{"symlink entry", []zipEntry{{name: "l", mode: 0o777, symlink: true, body: "x"}}},
		{"file entry", []zipEntry{{name: "f", mode: 0o644, body: "x"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restoreSeams(t)
			zipOpen = func(*zip.File) (io.ReadCloser, error) { return nil, errors.New("zip open boom") }
			s := serve(t, buildZip(t, tc.entries))
			_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
			if err == nil || !strings.Contains(err.Error(), "zip open boom") {
				t.Fatalf("err = %v; want zip open boom", err)
			}
		})
	}
}

func TestFetchTarZeroModeFallbacks(t *testing.T) {
	data := buildTar(t, []tarEntry{
		{name: "d/", typ: tar.TypeDir, mode: 0},
		{name: "d/f", typ: tar.TypeReg, mode: 0, body: "x"},
	})
	s := serve(t, data)
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tar", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "d"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("d mode = %v, %v; want 0755 fallback", fi.Mode(), err)
	}
	fi, err = os.Stat(filepath.Join(dir, "d", "f"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("d/f mode = %v, %v; want 0644 fallback", fi.Mode(), err)
	}
}

// TestFetchZipZeroModeFallback covers bk's permOr fallback (and writeFile) for a
// zip regular entry carrying no Unix mode bits — the tar path that used to
// exercise this now delegates to artifact.Extract.
func TestFetchZipZeroModeFallback(t *testing.T) {
	data := buildZip(t, []zipEntry{{name: "f", mode: 0, body: "x"}})
	s := serve(t, data)
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.zip", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "f"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("f mode = %v, %v; want 0644 fallback", fi.Mode(), err)
	}
}

// TestFetchZipRegCopyError covers writeFile's copy-error branch via a zip
// regular entry (the tar equivalent moved to artifact.Extract).
func TestFetchZipRegCopyError(t *testing.T) {
	restoreSeams(t)
	ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("copy boom") }
	data := buildZip(t, []zipEntry{{name: "f", mode: 0o644, body: "x"}})
	s := serve(t, data)
	_, err := Fetch(s.URL+"/pkg.zip", t.TempDir(), 0)
	if err == nil || !strings.Contains(err.Error(), "copy boom") {
		t.Fatalf("err = %v; want copy boom", err)
	}
}

func TestSafeTargetSkipsFullyStripped(t *testing.T) {
	if _, ok, err := safeTarget("/dest", "pkg-1.0", 1); err != nil || ok {
		t.Fatalf("safeTarget = ok %v, err %v; want skip", ok, err)
	}
	if _, ok, err := safeTarget("/dest", "./", 0); err != nil || ok {
		t.Fatalf("safeTarget(./) = ok %v, err %v; want skip", ok, err)
	}
}

func TestPermOr(t *testing.T) {
	if got := permOr(0o600, 0o644); got != 0o600 {
		t.Errorf("permOr(0600, 0644) = %o; want 0600", got)
	}
	if got := permOr(0, 0o644); got != 0o644 {
		t.Errorf("permOr(0, 0644) = %o; want 0644 fallback", got)
	}
}

func TestFetchGit(t *testing.T) {
	restoreSeams(t)
	osRemoveAll = func(string) error { return nil }
	var refs, dests []string
	gitPlainClone = func(dest string, isBare bool, o *gogit.CloneOptions) (*gogit.Repository, error) {
		refs = append(refs, o.ReferenceName.String())
		dests = append(dests, dest)
		if isBare || o.Depth != 1 || o.URL != "https://example.com/r.git" {
			// the "git+" prefix must be stripped to a plain transport scheme
			t.Errorf("clone opts = bare:%v depth:%d url:%q", isBare, o.Depth, o.URL)
		}
		return nil, nil // succeed on the first (tag) attempt
	}
	if _, err := FetchGit("git+https://example.com/r.git", "v1.2.3", "/tmp/dest"); err != nil {
		t.Fatalf("FetchGit: %v", err)
	}
	if len(refs) != 1 || refs[0] != "refs/tags/v1.2.3" || dests[0] != "/tmp/dest" {
		t.Fatalf("expected one tag-ref clone into dest, got refs=%v dests=%v", refs, dests)
	}
}

func TestFetchGitBranchFallback(t *testing.T) {
	restoreSeams(t)
	osRemoveAll = func(string) error { return nil }
	var refs []string
	gitPlainClone = func(_ string, _ bool, o *gogit.CloneOptions) (*gogit.Repository, error) {
		refs = append(refs, o.ReferenceName.String())
		if o.ReferenceName.IsTag() {
			return nil, errors.New("reference not found")
		}
		return nil, nil // the ref is a branch, not a tag → second attempt wins
	}
	if _, err := FetchGit("https://x/r.git", "main", "/tmp/dest"); err != nil {
		t.Fatalf("branch fallback: %v", err)
	}
	if len(refs) != 2 || refs[0] != "refs/tags/main" || refs[1] != "refs/heads/main" {
		t.Fatalf("expected tag then branch attempt, got %v", refs)
	}
}

func TestFetchGitError(t *testing.T) {
	restoreSeams(t)
	osRemoveAll = func(string) error { return nil }
	gitPlainClone = func(string, bool, *gogit.CloneOptions) (*gogit.Repository, error) {
		return nil, errors.New("clone failed")
	}
	_, err := FetchGit("https://x/r.git", "v1", "/tmp/dest")
	if err == nil || !strings.Contains(err.Error(), "clone failed") {
		t.Fatalf("err = %v; want clone failed", err)
	}
}

// TestExtractTarGzFile covers the local-sdist extractor: the happy strip-1 path
// and each error branch (open, gzip, dest mkdir).
func TestExtractTarGzFile(t *testing.T) {
	restoreSeams(t)

	// happy: a gzip'd tar with a top dir stripped away → file lands under dest.
	dir := t.TempDir()
	src := filepath.Join(dir, "pkg.tar.gz")
	data := gzWrap(t, buildTar(t, []tarEntry{
		{name: "pkg-1.0/", typ: tar.TypeDir, mode: 0o755},
		{name: "pkg-1.0/mod.py", typ: tar.TypeReg, mode: 0o644, body: "print(1)\n"},
	}))
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	if err := ExtractTarGzFile(src, dest, 1); err != nil {
		t.Fatalf("ExtractTarGzFile: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "mod.py")); err != nil || string(b) != "print(1)\n" {
		t.Errorf("extracted = %q, %v", b, err)
	}

	// open error: missing file.
	if err := ExtractTarGzFile(filepath.Join(dir, "nope.tar.gz"), dest, 1); err == nil {
		t.Error("expected open error")
	}

	// gzip error: not a gzip stream.
	bad := filepath.Join(dir, "bad.tar.gz")
	if err := os.WriteFile(bad, []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ExtractTarGzFile(bad, dest, 1); err == nil {
		t.Error("expected gzip error")
	}

	// mkdir(dest) error via the seam.
	osMkdirAll = failMkdirOn("out2")
	if err := ExtractTarGzFile(src, filepath.Join(dir, "out2"), 1); err == nil {
		t.Error("expected dest-mkdir error")
	}
}

// TestExtractRestoresModTimes is the libexpat trap, in miniature: a release
// tarball ships a GENERATED file (a man page) recorded as NEWER than the source
// it derives from, so make leaves it alone. Extraction must preserve that
// order — stamping every file with "now" re-orders them by archive position and
// make tries to regenerate, which killed libexpat 2.8.3 (no docbook2x-man).
func TestExtractRestoresModTimes(t *testing.T) {
	restoreSeams(t)
	src := time.Date(2026, 8, 10, 23, 50, 0, 0, time.UTC)
	gen := time.Date(2026, 8, 10, 23, 51, 0, 0, time.UTC) // generated LAST, archived FIRST

	t.Run("tar", func(t *testing.T) {
		s := serve(t, gzWrap(t, buildTar(t, []tarEntry{
			{name: "doc/", typ: tar.TypeDir, mode: 0o755},
			{name: "doc/xmlwf.1", typ: tar.TypeReg, mode: 0o644, body: "man\n", mod: gen},
			{name: "doc/xmlwf.xml", typ: tar.TypeReg, mode: 0o644, body: "<xml/>\n", mod: src},
		})))
		dir := t.TempDir()
		if _, err := Fetch(s.URL+"/pkg.tar.gz", dir, 0); err != nil {
			t.Fatal(err)
		}
		assertNewer(t, filepath.Join(dir, "doc/xmlwf.1"), filepath.Join(dir, "doc/xmlwf.xml"), gen)
	})

	t.Run("zip", func(t *testing.T) {
		s := serve(t, buildZip(t, []zipEntry{
			{name: "doc/xmlwf.1", mode: 0o644, body: "man\n", mod: gen},
			{name: "doc/xmlwf.xml", mode: 0o644, body: "<xml/>\n", mod: src},
		}))
		dir := t.TempDir()
		if _, err := Fetch(s.URL+"/pkg.zip", dir, 0); err != nil {
			t.Fatal(err)
		}
		assertNewer(t, filepath.Join(dir, "doc/xmlwf.1"), filepath.Join(dir, "doc/xmlwf.xml"), gen)
	})

	// tar records "no time" as the epoch, and that is restored faithfully: with
	// every file equally old, make still sees nothing to regenerate.
	t.Run("epoch is preserved", func(t *testing.T) {
		s := serve(t, gzWrap(t, buildTar(t, []tarEntry{
			{name: "x.txt", typ: tar.TypeReg, mode: 0o644, body: "x\n"},
		})))
		dir := t.TempDir()
		if _, err := Fetch(s.URL+"/pkg.tar.gz", dir, 0); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(filepath.Join(dir, "x.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.ModTime().UTC().Equal(time.Unix(0, 0).UTC()) {
			t.Fatalf("mtime = %v, want the archived epoch", fi.ModTime().UTC())
		}
	})

	// A genuinely absent time (no archive format records one) is left alone.
	t.Run("zero time is left alone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := restoreTime(path, time.Time{}); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !after.ModTime().Equal(before.ModTime()) {
			t.Fatalf("mtime changed: %v → %v", before.ModTime(), after.ModTime())
		}
	})

	// A failing utimes propagates rather than silently leaving a wrong mtime.
	// (The tar path's mtime-error branch now lives in and is covered by the
	// artifact package; here the zip extractor still uses bk's restoreTime.)
	t.Run("chtimes fails", func(t *testing.T) {
		osChtimes = func(string, time.Time, time.Time) error { return errors.New("boom") }
		defer func() { osChtimes = os.Chtimes }()
		for name, data := range map[string][]byte{
			"/pkg.zip": buildZip(t, []zipEntry{{name: "x", mode: 0o644, body: "x", mod: gen}}),
		} {
			s := serve(t, data)
			if _, err := Fetch(s.URL+name, t.TempDir(), 0); err == nil {
				t.Errorf("%s: want a set-mtime error", name)
			}
		}
	})
}

// assertNewer checks a is strictly newer than b, and that a kept the recorded
// time rather than "now".
func assertNewer(t *testing.T, a, b string, want time.Time) {
	t.Helper()
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	if !fa.ModTime().After(fb.ModTime()) {
		t.Fatalf("%s (%v) must stay newer than %s (%v) — make would regenerate it",
			filepath.Base(a), fa.ModTime(), filepath.Base(b), fb.ModTime())
	}
	if !fa.ModTime().UTC().Equal(want) {
		t.Fatalf("mtime = %v, want the archived %v", fa.ModTime().UTC(), want)
	}
}

// TestFetchGitReportsTheCommit covers what a git material is attested by. A tag
// can be deleted and re-cut at different content and the URL reads the same
// afterwards, so the commit is the only fixed point — and a repository whose
// HEAD cannot be read (a fresh init, no commits) must weaken the attestation
// rather than fail a build whose source is correctly checked out.
func TestFetchGitReportsTheCommit(t *testing.T) {
	restoreSeams(t)
	osRemoveAll = func(string) error { return nil }

	empty, err := gogit.PlainInit(t.TempDir(), false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	gitPlainClone = func(string, bool, *gogit.CloneOptions) (*gogit.Repository, error) { return empty, nil }
	if got, err := FetchGit("https://x/r.git", "v1", "/tmp/dest"); err != nil || got != "" {
		t.Errorf("empty repo: commit = %q, err = %v; want no commit and no failure", got, err)
	}

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := wt.Add("a.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	want, err := wt.Commit("one", &gogit.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(0, 0)},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	gitPlainClone = func(string, bool, *gogit.CloneOptions) (*gogit.Repository, error) { return repo, nil }
	got, err := FetchGit("https://x/r.git", "v1", "/tmp/dest")
	if err != nil {
		t.Fatalf("FetchGit: %v", err)
	}
	if got != want.String() {
		t.Errorf("commit = %q, want %q", got, want)
	}
}

// The mirror hook fires at the one moment the bytes exist on disk with their
// digest known — the caller of Fetch sees only the digest, and the temp file is
// gone the moment Fetch returns.
func TestFetchPopulatesTheMirror(t *testing.T) {
	s := serve(t, gzWrap(t, sampleTar(t)))
	defer s.Close()

	var gotPath, gotDigest, gotURL string
	var existed bool
	Mirror = func(path, sha, url string) {
		gotPath, gotDigest, gotURL = path, sha, url
		_, err := os.Stat(path)
		existed = err == nil
	}
	defer func() { Mirror = nil }()

	dir := t.TempDir()
	digest, err := Fetch(s.URL+"/x.tar.gz", dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != digest {
		t.Errorf("mirror saw digest %q, Fetch returned %q", gotDigest, digest)
	}
	if gotURL != s.URL+"/x.tar.gz" {
		t.Errorf("mirror saw url %q", gotURL)
	}
	if !existed {
		t.Error("the archive was not on disk when the mirror was called, which is the only thing the hook is for")
	}
	// And it is gone afterwards, which is why the hook cannot be moved later.
	if _, err := os.Stat(gotPath); err == nil {
		t.Error("Fetch left the archive behind")
	}
}

// With no mirror configured — the default — Fetch behaves exactly as before.
// The hook is an addition, not a dependency.
func TestFetchWithNoMirrorConfigured(t *testing.T) {
	Mirror = nil
	s := serve(t, gzWrap(t, sampleTar(t)))
	defer s.Close()
	dir := t.TempDir()
	if _, err := Fetch(s.URL+"/pkg.tar.gz", dir, 0); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkSampleTree(t, dir)
}

// The pin hook is consulted BEFORE the mirror, and a refusal fails the fetch
// rather than being swallowed the way a mirror failure is. Those two
// contracts are easy to confuse, so both halves are asserted here.
func TestFetchAsksThePinBeforeTellingTheMirror(t *testing.T) {
	srv := serve(t, gzWrap(t, sampleTar(t)))
	defer srv.Close()

	t.Run("a refusal fails the fetch and the mirror is never told", func(t *testing.T) {
		var mirrored bool
		Mirror = func(string, string, string) { mirrored = true }
		Pin = func(url, sha string) error {
			if sha == "" {
				t.Error("the pin was asked without a digest")
			}
			return fmt.Errorf("%w: refused on purpose", ErrSourcePinMismatch)
		}
		defer func() { Mirror, Pin = nil, nil }()

		_, err := Fetch(srv.URL+"/pinned.tar.gz", t.TempDir(), 1)
		if !errors.Is(err, ErrSourcePinMismatch) {
			t.Fatalf("Fetch = %v; want the pin's refusal", err)
		}
		if mirrored {
			t.Error("the mirror recorded bytes the pin had just refused, which would make the change the new truth")
		}
	})

	t.Run("a pass lets the fetch through", func(t *testing.T) {
		called := 0
		Pin = func(string, string) error { called++; return nil }
		defer func() { Pin = nil }()
		if _, err := Fetch(srv.URL+"/pinned.tar.gz", t.TempDir(), 1); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if called != 1 {
			t.Errorf("the pin was asked %d times; want 1", called)
		}
	})
}
