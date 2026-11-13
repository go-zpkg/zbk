package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

// stageBin makes <dir>/<project>/v<ver>/bin/<files...>.
func stageBin(t *testing.T, dir, project, ver string, files ...string) {
	t.Helper()
	bin := filepath.Join(dir, filepath.FromSlash(project), "v"+ver, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "/") {
			if err := os.MkdirAll(filepath.Join(bin, f), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(bin, f), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// providesBed writes a catalogue to disk and replaces the install seam with one
// that "installs" by staging what stage says, for the project asked about.
func providesBed(t *testing.T, cat artifact.Catalog, stage func(t *testing.T, dir, project string) []artifact.Resolved) (path, dir string) {
	t.Helper()
	body, err := artifact.MarshalCatalog(cat)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	pi := providesInstall
	providesInstall = func(roots map[string]string, d, _, _ string) ([]artifact.Resolved, error) {
		for p := range roots {
			return stage(t, d, p), nil
		}
		return nil, nil
	}
	t.Cleanup(func() { providesInstall = pi })
	return path, dir
}

// The two real findings of go-zpkg/bk#376, in one catalogue, reported APART.
// zlib.net ships minigzip.wasm and lists nothing; age lists age-keygen and
// ships only age.wasm. A third project, whose catalogue and artifact agree, is
// the control: a check that flags it is one nobody will read.
func TestProvidesReportsBothDirectionsSeparately(t *testing.T) {
	cat := artifact.Catalog{Projects: []artifact.CatalogProject{
		{Project: "zlib.net", Versions: []string{"1.3.2"}},
		{Project: "filippo.io/age", Versions: []string{"1.2.1"}, Provides: []string{"age", "age-keygen"}},
		{Project: "lua.org", Versions: []string{"5.4.9"}, Provides: []string{"lua", "luac"}},
		{Project: "unpublished.org"},
	}}
	path, dir := providesBed(t, cat, func(t *testing.T, d, p string) []artifact.Resolved {
		switch p {
		case "zlib.net":
			stageBin(t, d, p, "1.3.2", "minigzip.wasm")
			return []artifact.Resolved{{Project: p, Version: artifact.ParseVer("1.3.2")}, {Project: "other.org", Version: artifact.ParseVer("9")}}
		case "filippo.io/age":
			stageBin(t, d, p, "1.2.1", "age.wasm")
		case "lua.org":
			// README has no .wasm suffix, .hidden is a dot-file, sub/ a dir:
			// none of them is a command.
			stageBin(t, d, p, "5.4.9", "lua.wasm", "luac.wasm", "README", ".hidden.wasm", "sub/")
		}
		return []artifact.Resolved{{Project: p, Version: artifact.ParseVer(map[string]string{"filippo.io/age": "1.2.1", "lua.org": "5.4.9"}[p])}}
	})
	var out, errb bytes.Buffer
	code := runProvides([]string{"--catalog", path, "--platform", "wasip1/wasm", "--store", dir, "--fail"}, &out, &errb)
	if code != 1 {
		t.Fatalf("code=%d, want 1 (--fail with findings)\n%s%s", code, out.String(), errb.String())
	}
	got := out.String()
	for _, want := range []string{
		`zlib.net                           FILE, NOT LISTED  bin/minigzip.wasm is in the artifact and ` + "`provides`" + ` omits "minigzip"`,
		`filippo.io/age                     LISTED, NO FILE   provides "age-keygen" but the artifact has no bin/age-keygen.wasm`,
		"1 listed with no file",
		"1 file(s) not listed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "lua.org ") || strings.Contains(got, "unpublished") {
		t.Errorf("a project that agrees, or has no artifact, was flagged:\n%s", got)
	}
	if strings.Contains(got, "could not be checked") {
		t.Errorf("nothing was unreadable:\n%s", got)
	}
}

// Without --fail the findings are information, exit 0; a clean catalogue exits
// 0 under --fail too.
func TestProvidesExitCodes(t *testing.T) {
	cat := artifact.Catalog{Projects: []artifact.CatalogProject{{Project: "a.org", Versions: []string{"1"}, Provides: []string{"a"}}}}
	for _, tc := range []struct {
		name  string
		files []string
		args  []string
		want  int
	}{
		{"finding, no --fail", []string{"b"}, nil, 0},
		{"finding, --fail", []string{"b"}, []string{"--fail"}, 1},
		{"clean, --fail", []string{"a"}, []string{"--fail"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := providesBed(t, cat, func(t *testing.T, d, p string) []artifact.Resolved {
				stageBin(t, d, p, "1", tc.files...)
				return []artifact.Resolved{{Project: p, Version: artifact.ParseVer("1")}}
			})
			var out, errb bytes.Buffer
			args := append([]string{"--catalog", path, "--platform", "linux/x86-64"}, tc.args...)
			if code := runProvides(args, &out, &errb); code != tc.want {
				t.Fatalf("code=%d, want %d\n%s%s", code, tc.want, out.String(), errb.String())
			}
		})
	}
}

// A library has no bin/ at all; that is "no commands", not an error, and a
// catalogue that lists none agrees with it.
func TestProvidesLibraryWithNoBinDirectory(t *testing.T) {
	cat := artifact.Catalog{Projects: []artifact.CatalogProject{{Project: "lib.org", Versions: []string{"1"}}}}
	path, _ := providesBed(t, cat, func(t *testing.T, d, p string) []artifact.Resolved {
		if err := os.MkdirAll(filepath.Join(d, p, "v1", "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		return []artifact.Resolved{{Project: p, Version: artifact.ParseVer("1")}}
	})
	var out, errb bytes.Buffer
	if code := runProvides([]string{"--catalog", path, "--fail"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d\n%s%s", code, out.String(), errb.String())
	}
}

// Everything that stops a project being checked is counted and (under --fail)
// fatal: a check that skipped it silently would report a clean run.
func TestProvidesUnreadableProjectsAreCounted(t *testing.T) {
	cat := artifact.Catalog{Projects: []artifact.CatalogProject{
		{Project: "boom.org", Versions: []string{"1"}},
		{Project: "ghost.org", Versions: []string{"1"}},
		{Project: "binfile.org", Versions: []string{"1"}},
	}}
	path, _ := providesBed(t, cat, func(t *testing.T, d, p string) []artifact.Resolved {
		switch p {
		case "boom.org":
			return nil // installed, closure does not name it
		case "binfile.org":
			// bin is a FILE: ReadDir fails with something other than not-exist.
			v := filepath.Join(d, p, "v1")
			if err := os.MkdirAll(v, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(v, "bin"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []artifact.Resolved{{Project: p, Version: artifact.ParseVer("1")}}
		}
		return nil
	})
	pi := providesInstall
	providesInstall = func(roots map[string]string, d, o, a string) ([]artifact.Resolved, error) {
		if _, ok := roots["ghost.org"]; ok {
			return nil, errors.New("no such artifact")
		}
		return pi(roots, d, o, a)
	}
	t.Cleanup(func() { providesInstall = pi })

	var out, errb bytes.Buffer
	code := runProvides([]string{"--catalog", path, "--fail", "boom.org", "ghost.org", "binfile.org", "missing.org"}, &out, &errb)
	if code != 1 {
		t.Fatalf("code=%d, want 1", code)
	}
	if !strings.Contains(out.String(), "4 project(s) could not be checked") {
		t.Errorf("output:\n%s", out.String())
	}
	for _, want := range []string{"no such artifact", "closure does not name it", "missing.org: not in the catalogue"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errb.String())
		}
	}
}

func TestProvidesUsage(t *testing.T) {
	ok := artifact.Catalog{Projects: []artifact.CatalogProject{{Project: "a.org", Versions: []string{"1"}}}}
	none := artifact.Catalog{Projects: []artifact.CatalogProject{{Project: "a.org"}}}
	pathOK, _ := providesBed(t, ok, func(*testing.T, string, string) []artifact.Resolved { return nil })
	pathNone, _ := providesBed(t, none, func(*testing.T, string, string) []artifact.Resolved { return nil })
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"bad flag", []string{"--nope"}, 2},
		{"no catalogue", nil, 2},
		{"bad platform", []string{"--catalog", pathOK, "--platform", "linux"}, 2},
		{"missing file", []string{"--catalog", filepath.Join(t.TempDir(), "absent.json")}, 1},
		{"bad json", []string{"--catalog", bad}, 1},
		{"nothing published", []string{"--catalog", pathNone}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := runProvides(tc.args, &out, &errb); code != tc.want {
				t.Errorf("code=%d, want %d: %s", code, tc.want, errb.String())
			}
		})
	}
}

func TestProvidesTempDirFailureAndDefaultStore(t *testing.T) {
	cat := artifact.Catalog{Projects: []artifact.CatalogProject{{Project: "a.org", Versions: []string{"1"}, Provides: []string{"a"}}}}
	path, _ := providesBed(t, cat, func(t *testing.T, d, p string) []artifact.Resolved {
		stageBin(t, d, p, "1", "a")
		return []artifact.Resolved{{Project: p, Version: artifact.ParseVer("1")}}
	})
	var made string
	pt := providesTempDir
	t.Cleanup(func() { providesTempDir = pt })
	providesTempDir = func(dir, pat string) (string, error) {
		d, err := pt(dir, pat)
		made = d
		return d, err
	}
	var out, errb bytes.Buffer
	if code := runProvides([]string{"--catalog", path}, &out, &errb); code != 0 {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	if _, err := os.Stat(made); !os.IsNotExist(err) {
		t.Errorf("the temporary store %q was not removed", made)
	}
	providesTempDir = func(string, string) (string, error) { return "", errors.New("disk full") }
	if code := runProvides([]string{"--catalog", path}, &out, &errb); code != 1 {
		t.Errorf("code=%d, want 1", code)
	}
}

// A catalogue artifact's tarball is read as well as the bare JSON.
func TestReadCatalogFileTarball(t *testing.T) {
	cat := artifact.Catalog{Projects: []artifact.CatalogProject{{Project: "a.org", Provides: []string{"a"}}}}
	tgz, err := artifact.CatalogTarball(cat)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "catalog.tar.gz")
	if err := os.WriteFile(p, tgz, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readCatalogFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := got.Lookup("a.org"); !ok || strings.Join(e.Provides, " ") != "a" {
		t.Errorf("got %+v", got)
	}
}

// `bk provides` is reachable through the dispatch.
func TestProvidesIsDispatched(t *testing.T) {
	if code, _, _ := run2(t, "provides"); code != 2 {
		t.Errorf("code=%d, want 2 (--catalog is required)", code)
	}
}

func TestExeSuffix(t *testing.T) {
	for osn, want := range map[string]string{"wasip1": ".wasm", "windows": ".exe", "linux": "", "darwin": ""} {
		if got := exeSuffix(osn); got != want {
			t.Errorf("exeSuffix(%q) = %q, want %q", osn, got, want)
		}
	}
}
