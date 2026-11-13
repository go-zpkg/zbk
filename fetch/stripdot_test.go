package fetch

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// zipOf builds a zip whose members are exactly the given names.
func zipOf(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(n, "/") {
			if _, err := w.Write([]byte(n)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func namesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out
}

// TestZipStripCountsALeadingDotLikeTarDoes: the two extractors must agree about
// what `strip-components` means. The expectations match GNU tar's on the same
// shape, measured in go-zpkg/artifact#69.
func TestZipStripCountsALeadingDotLikeTarDoes(t *testing.T) {
	data := zipOf(t, "./top/CMakeLists.txt", "./top/sub/CMakeLists.txt")
	for _, tc := range []struct {
		strip int
		want  []string
	}{
		{1, []string{"top/CMakeLists.txt", "top/sub/CMakeLists.txt"}},
		{2, []string{"CMakeLists.txt", "sub/CMakeLists.txt"}},
	} {
		dir := t.TempDir()
		if err := extractZip(data, dir, tc.strip); err != nil {
			t.Fatalf("strip %d: %v", tc.strip, err)
		}
		got := namesUnder(t, dir)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("strip %d: %v, want %v", tc.strip, got, tc.want)
		}
	}
}

// TestZipStripIsUnchangedWithoutALeadingDot: the control. Without "./" nothing
// about the existing behaviour may move.
func TestZipStripIsUnchangedWithoutALeadingDot(t *testing.T) {
	data := zipOf(t, "top/CMakeLists.txt", "top/sub/CMakeLists.txt")
	dir := t.TempDir()
	if err := extractZip(data, dir, 1); err != nil {
		t.Fatal(err)
	}
	want := []string{"CMakeLists.txt", "sub/CMakeLists.txt"}
	if got := namesUnder(t, dir); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("%v, want %v", got, want)
	}
}

func TestStripComponentsKeepsDotDropsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"./a/b", []string{".", "a", "b"}},
		{"a//b/", []string{"a", "b"}},
		{"", nil},
	} {
		if got := stripComponents(tc.name); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q -> %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestZipStripStillRefusesToEscape: counting "." must not let the strip count
// swallow a ".." and turn a member that names its way out of the tree into one
// that is quietly written inside it.
func TestZipStripStillRefusesToEscape(t *testing.T) {
	dir := t.TempDir()
	if err := extractZip(zipOf(t, "./a/../../escaped"), dir, 1); err == nil {
		t.Fatal("a member escaping the root was accepted")
	}
	if got := namesUnder(t, dir); len(got) != 0 {
		t.Errorf("it wrote %v", got)
	}
}
