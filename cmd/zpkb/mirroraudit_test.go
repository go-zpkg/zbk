package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/bottlepkg"
	"github.com/go-zpkg/zpkb/fixup"
	"github.com/klauspost/compress/zstd"
)

// machoBytes builds a minimal thin Mach-O64 (LE) carrying the given load
// commands. cmd 0xc is LC_LOAD_DYLIB (string at offset 24), 0x8000001c is
// LC_RPATH (string at offset 12).
func machoBytes(cmds ...[2]any) []byte {
	le := binary.LittleEndian
	var body []byte
	for _, c := range cmds {
		cmd, str := c[0].(uint32), c[1].(string)
		strOff := 24
		if cmd == 0x8000001c {
			strOff = 12
		}
		size := strOff + len(str) + 1
		for size%8 != 0 {
			size++
		}
		cb := make([]byte, size)
		le.PutUint32(cb[0:], cmd)
		le.PutUint32(cb[4:], uint32(size))
		le.PutUint32(cb[8:], uint32(strOff))
		copy(cb[strOff:], str)
		body = append(body, cb...)
	}
	buf := make([]byte, 32+len(body))
	le.PutUint32(buf[0:], 0xfeedfacf)
	le.PutUint32(buf[4:], 0x0100000c)
	le.PutUint32(buf[12:], 6)
	le.PutUint32(buf[16:], uint32(len(cmds)))
	le.PutUint32(buf[20:], uint32(len(body)))
	copy(buf[32:], body)
	return buf
}

// gzBottle writes a .tar.gz whose entries are name->content, as a bottle
// tarball is laid out: `<project>/v<version>/…`.
func gzBottle(t *testing.T, files map[string][]byte) string {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "v2.55.0.tar.gz")
	if err := os.WriteFile(p, raw.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// zstBottle is gzBottle in the codec the factory actually publishes.
func zstBottle(t *testing.T, files map[string][]byte) string {
	t.Helper()
	var raw bytes.Buffer
	zw, err := zstd.NewWriter(&raw)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "v2.55.0.tar.zst")
	if err := os.WriteFile(p, raw.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const (
	lcLoad  = uint32(0xc)
	lcRpath = uint32(0x8000001c)
)

// TestAuditMirroredBottleFindsWhatFixupNeverSaw reproduces git-scm.org 2.55.0's
// shape: a qualified @rpath reference to a sibling package, and one rpath —
// the build machine's own absolute path. A mirror is never unpacked, so no
// guard has ever seen it.
func TestAuditMirroredBottleFindsWhatFixupNeverSaw(t *testing.T) {
	tb := gzBottle(t, map[string][]byte{
		"git-scm.org/v2.55.0/libexec/git": machoBytes(
			[2]any{lcLoad, "@rpath/zlib.net/v1.3.2/lib/libz.1.dylib"},
			[2]any{lcRpath, "/Users/runner/.pkgx"}),
		"git-scm.org/v2.55.0/lib/libok.dylib": machoBytes(
			[2]any{lcLoad, "@rpath/zlib.net/v1.3.2/lib/libz.1.dylib"},
			[2]any{lcRpath, "@loader_path/../../.."}),
		// Most of a bottle is not Mach-O and must cost nothing.
		"git-scm.org/v2.55.0/bin/git":              []byte("#!/bin/sh\nexec true\n"),
		"git-scm.org/v2.55.0/share/man/man1/git.1": []byte(".TH GIT 1\n"),
	})
	checked, problems, err := auditMirroredBottle(tb, bottle.ExtTarGz, "git-scm.org", "2.55.0")
	if err != nil {
		t.Fatal(err)
	}
	if checked != 2 {
		t.Fatalf("checked %d Mach-O, want 2 (the shell script and the man page are not)", checked)
	}
	if len(problems) != 1 {
		t.Fatalf("reported %d problem(s), want 1: %v", len(problems), problems)
	}
	if !errors.Is(problems[0], fixup.ErrBuilderOnlyRpath) {
		t.Errorf("problem is %v, want ErrBuilderOnlyRpath", problems[0])
	}
	if !strings.Contains(problems[0].Error(), filepath.Join("libexec", "git")) {
		t.Errorf("problem does not name libexec/git: %v", problems[0])
	}
}

// TestAuditMirroredBottleIsQuietOnARelocatableOne is the negative control: the
// same reference, reachable through a relative rpath, is not a finding.
func TestAuditMirroredBottleIsQuietOnARelocatableOne(t *testing.T) {
	tb := gzBottle(t, map[string][]byte{
		"lloyd.github.io/yajl/v2.1.0/lib/libyajl.2.dylib": machoBytes(
			[2]any{lcLoad, "@rpath/zlib.net/v1.3.2/lib/libz.1.dylib"},
			[2]any{lcRpath, "@loader_path/../../../.."},
			[2]any{lcRpath, "/Users/runner/.pkgx"}),
	})
	checked, problems, err := auditMirroredBottle(tb, bottle.ExtTarGz, "lloyd.github.io/yajl", "2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if checked != 1 || len(problems) != 0 {
		t.Errorf("checked=%d problems=%v, want 1 and none", checked, problems)
	}
}

// TestAuditMirroredBottleSaysWhenItCouldNotRead: a compression the audit cannot
// open must report an error, never zero findings — a scan that could not read
// is not a scan that found nothing.
func TestAuditMirroredBottleSaysWhenItCouldNotRead(t *testing.T) {
	tb := gzBottle(t, map[string][]byte{"x/v1/bin/x": []byte("hi")})
	_, _, err := auditMirroredBottle(tb, ".tar.br", "x", "1")
	if err == nil {
		t.Fatal("an unhandled compression returned no error")
	}
	// The EXTENSION, not a phrase. The wording moved when this stopped
	// hand-rolling its decoder and asked bottle.Decompressor, and an assertion
	// on the sentence would have made a correct change look like a regression.
	// What a reader needs is which compression was refused.
	if !strings.Contains(err.Error(), ".tar.br") {
		t.Errorf("error does not name the compression it could not read: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot audit") {
		t.Errorf("error does not say what failed: %v", err)
	}
}

// rawBottle writes an archive body verbatim under a given name, so a test can
// hand the audit bytes that are not what their extension claims.
func rawBottle(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLooksMachORejectsAShortRead(t *testing.T) {
	if looksMachO([]byte{0xfe, 0xed}) {
		t.Error("two bytes cannot be a Mach-O magic")
	}
	if !looksMachO([]byte{0xca, 0xfe, 0xba, 0xbe, 0x00}) {
		t.Error("a fat magic was not recognised")
	}
}

// TestAuditMirroredBottleReportsWhatItCannotOpen covers the three ways the
// archive itself refuses to be read. Each must return an error naming the
// cause: a mirror that could not be audited must never read as one that was.
func TestAuditMirroredBottleReportsWhatItCannotOpen(t *testing.T) {
	for _, tc := range []struct {
		name, ext, want string
		path            func() string
	}{
		{"missing file", bottle.ExtTarGz, "no such file",
			func() string { return filepath.Join(t.TempDir(), "absent.tar.gz") }},
		{"not gzip", bottle.ExtTarGz, "gzip",
			func() string { return rawBottle(t, "x.tar.gz", []byte("not a gzip stream at all")) }},
		{"not xz", bottle.ExtTarXz, "xz",
			func() string { return rawBottle(t, "x.tar.xz", []byte("not an xz stream at all")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := auditMirroredBottle(tc.path(), tc.ext, "p", "1")
			if err == nil {
				t.Fatalf("no error for %s", tc.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestAuditMirroredBottleStopsOnATruncatedArchive: a tar that ends mid-entry is
// an unreadable archive, not an empty one.
func TestAuditMirroredBottleStopsOnATruncatedArchive(t *testing.T) {
	full := gzBottle(t, map[string][]byte{"p/v1/lib/a.dylib": machoBytes([2]any{lcRpath, "@loader_path"})})
	b, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	cut := rawBottle(t, "cut.tar.gz", b[:len(b)/2])
	if _, _, err := auditMirroredBottle(cut, bottle.ExtTarGz, "p", "1"); err == nil {
		t.Error("a truncated archive reported no error")
	}
}

// TestAuditMirroredBottleSkipsWhatIsNotAFile: directories and symlinks carry no
// content to audit, and an entry naming its way out of the tree is not written
// anywhere — a tarball does not get to choose where the audit writes.
func TestAuditMirroredBottleSkipsWhatIsNotAFile(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, h := range []*tar.Header{
		{Name: "p/v1/lib/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "p/v1/lib/link.dylib", Typeflag: tar.TypeSymlink, Linkname: "real.dylib"},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	escape := machoBytes([2]any{lcRpath, "@loader_path"})
	if err := tw.WriteHeader(&tar.Header{
		Name: "../escaped.dylib", Mode: 0o755, Size: int64(len(escape)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(escape); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := rawBottle(t, "odd.tar.gz", raw.Bytes())
	checked, problems, err := auditMirroredBottle(p, bottle.ExtTarGz, "p", "1")
	if err != nil {
		t.Fatal(err)
	}
	if checked != 0 || len(problems) != 0 {
		t.Errorf("checked=%d problems=%v, want 0 and none", checked, problems)
	}
}

// TestAuditMirroredBottleReportsFilesystemFailures walks the four seams: each
// is a real failure a user could hit (a full disk, a read-only temp) and each
// must surface rather than silently audit nothing.
func TestAuditMirroredBottleReportsFilesystemFailures(t *testing.T) {
	good := func(t *testing.T) string {
		return gzBottle(t, map[string][]byte{
			"p/v1/lib/a.dylib": machoBytes([2]any{lcRpath, "@loader_path"}),
		})
	}
	boom := errors.New("boom")
	for _, tc := range []struct {
		name  string
		patch func(t *testing.T)
	}{
		{"temp dir", func(t *testing.T) {
			old := auditMkdirTemp
			auditMkdirTemp = func(string, string) (string, error) { return "", boom }
			t.Cleanup(func() { auditMkdirTemp = old })
		}},
		{"mkdir", func(t *testing.T) {
			old := auditMkdirAll
			auditMkdirAll = func(string, os.FileMode) error { return boom }
			t.Cleanup(func() { auditMkdirAll = old })
		}},
		{"create", func(t *testing.T) {
			old := auditOpenFile
			auditOpenFile = func(string, int, os.FileMode) (*os.File, error) { return nil, boom }
			t.Cleanup(func() { auditOpenFile = old })
		}},
		{"copy", func(t *testing.T) {
			old := ioCopy
			ioCopy = func(io.Writer, io.Reader) (int64, error) { return 0, boom }
			t.Cleanup(func() { ioCopy = old })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb := good(t)
			tc.patch(t)
			if _, _, err := auditMirroredBottle(tb, bottle.ExtTarGz, "p", "1"); !errors.Is(err, boom) {
				t.Errorf("error is %v, want boom", err)
			}
		})
	}
}

// TestAuditMirroredBottleReportsAnUnopenableArchive covers the os.Open seam,
// which a missing file already reaches — this pins the message.
func TestAuditMirroredBottleReportsAnUnopenableArchive(t *testing.T) {
	old := auditOpen
	auditOpen = func(string) (*os.File, error) { return nil, errors.New("sealed") }
	t.Cleanup(func() { auditOpen = old })
	if _, _, err := auditMirroredBottle("whatever", bottle.ExtTarGz, "p", "1"); err == nil ||
		!strings.Contains(err.Error(), "sealed") {
		t.Errorf("error is %v, want sealed", err)
	}
}

// TestRunFactoryMirrorReportsANonRelocatableBottle is the wiring: a darwin
// mirror run says, at publish time, what fixup's guards never got to see.
// Five broken files, so the "… and N more" cut-off is exercised too.
func TestRunFactoryMirrorReportsANonRelocatableBottle(t *testing.T) {
	files := map[string][]byte{}
	for _, n := range []string{"git", "git-remote-https", "scalar", "git-shell", "git-cvsserver"} {
		files["git-scm.org/v2.55.0/libexec/"+n] = machoBytes(
			[2]any{lcLoad, "@rpath/zlib.net/v1.3.2/lib/libz.1.dylib"},
			[2]any{lcRpath, "/Users/runner/.pkgx"})
	}
	body, err := os.ReadFile(gzBottle(t, files))
	if err != nil {
		t.Fatal(err)
	}

	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "git-scm.org", "versions:\n  github: git/git/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"git-scm.org": {"2.55.0"}},
		func(_, _, _, _ string) ([]byte, string, error) { return body, ".tar.gz", nil })

	if code := h.run(t, "--platform", "darwin/aarch64", "--recipes", "git-scm.org",
		"--mirror-from", "https://dist.pkgx.dev/", "--bottles", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	errs := h.errb.String()
	for _, want := range []string{
		"NOT RELOCATABLE git-scm.org 2.55.0 (darwin/aarch64): 5 of 5 Mach-O",
		"sibling package reachable only through an absolute rpath",
		"… and 2 more",
	} {
		if !strings.Contains(errs, want) {
			t.Fatalf("stderr missing %q:\n%s", want, errs)
		}
	}
	// It REPORTS: the bottle is still published. Refusing is packages#147's call.
	if !strings.Contains(h.out.String(), "✅ MIRRORED git-scm.org 2.55.0 darwin/aarch64") {
		t.Errorf("the audit must not stop the publish:\n%s", h.out.String())
	}
}

// TestRunFactoryMirrorSaysWhenItCouldNotAudit: a compression the audit cannot
// open is reported as such, never as a clean bill.
func TestRunFactoryMirrorSaysWhenItCouldNotAudit(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "git-scm.org", "versions:\n  github: git/git/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"git-scm.org": {"2.55.0"}},
		func(_, _, _, _ string) ([]byte, string, error) { return []byte("zzzz"), ".tar.br", nil })

	if code := h.run(t, "--platform", "darwin/aarch64", "--recipes", "git-scm.org",
		"--mirror-from", "https://d", "--bottles", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "not audited: cannot audit") {
		t.Fatalf("stderr missing the unaudited notice:\n%s", h.errb.String())
	}
}

// TestRunFactoryMirrorDoesNotAuditLinux: the guards are Mach-O. A linux mirror
// must not pay a decompression for a check that cannot apply.
func TestRunFactoryMirrorDoesNotAuditLinux(t *testing.T) {
	h := newFactoryHarness(t)
	writeClosureRecipe(t, h.pantry, "gnu.org/glibc", "versions:\n  github: a/glibc/tags\nbuild: make\n")
	withMirrorSeams(t, map[string][]string{"gnu.org/glibc": {"2.44.0"}},
		func(_, _, _, _ string) ([]byte, string, error) { return []byte("not even an archive"), ".tar.gz", nil })

	if code := h.run(t, "--recipes", "gnu.org/glibc", "--mirror-from", "https://d",
		"--bottles", filepath.Join(t.TempDir(), "dist")); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.Contains(h.errb.String(), "not audited") || strings.Contains(h.errb.String(), "NOT RELOCATABLE") {
		t.Errorf("linux must not be audited:\n%s", h.errb.String())
	}
}

// TestAuditMirroredBottleReadsTheDEFAULTCodec. The switch this replaced knew xz
// and gzip and sent .tar.zst — which is what bottlepkg.Codec is — down its
// error arm. The audit therefore refused every bottle the factory publishes
// today, and said so politely enough that it read as a gap rather than as
// total coverage of nothing.
func TestAuditMirroredBottleReadsTheDEFAULTCodec(t *testing.T) {
	if bottlepkg.Codec != bottle.ExtTarZst {
		t.Skipf("the default codec is %s; this test is about the one that is published", bottlepkg.Codec)
	}
	tb := zstBottle(t, map[string][]byte{
		"x/v1/lib/a.dylib": machoBytes([2]any{lcRpath, "@loader_path/../../.."}),
	})
	checked, problems, err := auditMirroredBottle(tb, bottle.ExtTarZst, "x", "1")
	if err != nil {
		t.Fatalf("the default codec must be auditable: %v", err)
	}
	if checked != 1 || len(problems) != 0 {
		t.Errorf("checked=%d problems=%v, want 1 and none", checked, problems)
	}
}
