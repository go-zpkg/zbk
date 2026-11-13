package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/buildscript"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/fixup"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

var errBoom = errors.New("boom")

// testBuildHash stands in for a build's identity where a test only wants the
// SCRATCH paths — Root, Build, Home, Test — which do not depend on it.
//
// ⛔ A FIXED STRING, AND NEVER COMPARED AGAINST A REAL IDENTITY. A test that
// asserts something about the INSTALL prefix has to ask Identity() for the
// real hash, the way the build does; using this one there would assert that
// the prefix contains a constant the test itself chose.
const testBuildHash = "abcdefghijklmnop"

// origLogf snapshots the real logf seam so tests can mute it and restore after.
var origLogf = logf

// tenv points config at temp dirs so no real ZPKG_DIR/data-home is touched.
func tenv(t *testing.T) {
	t.Setenv("ZPKG_DIR", filepath.Join(t.TempDir(), "pkgx"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "data"))
	t.Setenv("ZPKG_PANTRY_DIR", "")
	t.Setenv("ZPKG_PANTRY_PATH", "")
}

func okRecipe() *pantry.Recipe {
	return &pantry.Recipe{
		Distributable: map[string]any{"url": "https://x/v{{version.raw}}.tar.gz", "strip-components": 1},
		Dependencies:  map[string]any{"openssl.org": "^1.1"},
		Build:         map[string]any{"script": []any{"make install"}, "dependencies": map[string]any{"freedesktop.org/pkg-config": "^0.29"}},
	}
}

// okRunner returns a Runner whose stubs all succeed; its Run stub creates the
// +brewing install dir so the subsequent rename works.
//
// ⛔ THE STUB READS THE STAGING DIR OFF THE RUNNER RATHER THAN COMPUTING IT.
// It is named after the build's IDENTITY, which is a function of the recipe
// and the resolved closure — neither of which a stub has. A real script
// learns it because moustache substituted it in; this one reads
// `r.BuildInstall`, which Build sets before calling Run. Recomputing it here
// would be a second definition of the identity, free to drift from the first,
// and it drifted the moment the hash stopped being a constant.
func okRunner(project string, tgt target.Target) *Runner {
	r := &Runner{
		PickVersion:    func(string, string) (string, error) { return "1.2.3", nil },
		ResolveVersion: func(any, string) (string, string, error) { return "1.2.3", "v1.2.3", nil },
		Fetch:          func(string, string, int) (string, error) { return "", nil },
		FetchGit:       func(string, string, string) (string, error) { return "", nil },
		Touch:          func(string) error { return nil },
		FixUp:          func(fixup.Options) error { return nil },
		WriteBottle:    func(_, _, _, _, _, out string) (string, error) { return filepath.Join(out, "b.tar.gz"), nil },
		ZpkgxBin:       "/pkgx/bin/pkgx", BashPath: "/bin/bash",
	}
	r.Run = func(string, []string) error { return os.MkdirAll(r.BuildInstall, 0o755) }
	return r
}

// seedInstall runs one stubbed build so a real, hashed install prefix exists,
// and returns it.
//
// ⛔ THE PREFIX IS OBTAINED FROM THE PIPELINE, NOT COMPUTED BESIDE IT. A test
// that needs "a version of this already installed" used to write
// `config.Compute(project, version, tgt).Install` itself; now that the
// directory name carries the build's identity, a test that composed it would
// be asserting against a path the build never uses — and the assertions here
// ("the install survived", "the install was replaced") would both pass on a
// directory nothing touches.
func seedInstall(t *testing.T, project string, tgt target.Target) string {
	t.Helper()
	res, err := okRunner(project, tgt).Build(okRecipe(), project, "*", tgt, tgt, "")
	if err != nil {
		t.Fatalf("seeding an install: %v", err)
	}
	if res.Install == "" {
		t.Fatal("the build reported no install prefix")
	}
	return res.Install
}

func TestBuildHappyPath(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)
	res, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "1.2.3" || res.BottlePath == "" || res.ScriptPath == "" {
		t.Errorf("result = %+v", res)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	s := string(b)
	// the script wires deps + base toolchain + the user script + a cd to srcroot
	if !strings.Contains(s, `"+openssl.org^1.1"`) || !strings.Contains(s, `"+gnu.org/autoconf"`) || !strings.Contains(s, "make install") {
		t.Errorf("script missing pieces:\n%s", s)
	}
	// no dist → no bottle
	r2 := okRunner("acme.org/tool", tgt)
	res2, err := r2.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, "")
	if err != nil || res2.BottlePath != "" {
		t.Errorf("no-dist: %+v %v", res2, err)
	}
}

// TestBuildVersionTagExpands proves end-to-end that a distributable URL using
// {{version.tag}} (and the space-padded {{ version.tag }}) is fetched with the
// raw git tag from ResolveVersion — the exact bug that 404'd ~89 recipes — and
// that an empty tag falls back to the version string.
func TestBuildVersionTagExpands(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	distURL := "https://gh/o/r/releases/download/{{version.tag}}/{{ version.tag }}.tar.gz"

	run := func(tag, wantURL string) {
		tenv(t)
		r := okRunner("acme.org/tool", tgt)
		r.ResolveVersion = func(any, string) (string, string, error) { return "1.2.3", tag, nil }
		var fetched string
		r.Fetch = func(url, dest string, _ int) (string, error) {
			fetched = url
			return "", os.MkdirAll(dest, 0o755)
		}
		rec := okRecipe()
		rec.Distributable = distURL
		if _, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, ""); err != nil {
			t.Fatalf("build: %v", err)
		}
		if fetched != wantURL {
			t.Fatalf("fetched %q; want %q", fetched, wantURL)
		}
	}
	// raw git tag v1.2.3 → both moustache spellings expand to it
	run("v1.2.3", "https://gh/o/r/releases/download/v1.2.3/v1.2.3.tar.gz")
	// empty tag → fall back to the version string
	run("", "https://gh/o/r/releases/download/1.2.3/1.2.3.tar.gz")
}

func TestBuildWithResolveDep(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)
	r.ResolveDep = func(string, string) (string, error) { return "9.9.9", nil }
	rec := okRecipe()
	// a build script that references {{deps.<project>.prefix}} so the resolved
	// token actually expands into the generated script
	rec.Build = map[string]any{"script": []any{"./configure --with-ssl={{deps.openssl.org.prefix}}"}}
	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	if !strings.Contains(string(b), "openssl.org/v9.9.9") {
		t.Errorf("resolved dep prefix not expanded in script:\n%s", b)
	}
}

func TestBuildGitAndNoDistributable(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	// git distributable
	rec := okRecipe()
	rec.Distributable = map[string]any{"url": "https://git/repo", "ref": "v{{version.raw}}"}
	r := okRunner("g/p", tgt)
	gitCalled := false
	r.FetchGit = func(_, ref, _ string) (string, error) {
		gitCalled = true
		if ref != "v1.2.3" {
			t.Errorf("git ref = %q", ref)
		}
		return "cafe1234", nil
	}
	res, err := r.Build(rec, "g/p", "*", tgt, tgt, "")
	if err != nil || !gitCalled {
		t.Errorf("git build: %v called=%v", err, gitCalled)
	}
	// A git source is recorded by its commit; there is no archive to hash.
	if res.Source.Commit != "cafe1234" || res.Source.SHA256 != "" || res.Source.URI != "https://git/repo" {
		t.Errorf("git source = %+v", res.Source)
	}
	// nil distributable → fetch skipped entirely
	rec2 := okRecipe()
	rec2.Distributable = nil
	r2 := okRunner("n/p", tgt)
	r2.Fetch = func(string, string, int) (string, error) { t.Fatal("fetch must not run"); return "", nil }
	if _, err := r2.Build(rec2, "n/p", "*", tgt, tgt, ""); err != nil {
		t.Fatal(err)
	}
}

func TestBuildErrorBranches(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	restore := func() {
		osRemoveAll, osMkdirAll, osWriteFile, osRename = os.RemoveAll, os.MkdirAll, os.WriteFile, os.Rename
		writeLibexec = buildscript.WriteLibexecFor
	}

	cases := map[string]func(r *Runner){
		"resolveversion": func(r *Runner) {
			r.ResolveVersion = func(any, string) (string, string, error) { return "", "", errBoom }
		},
		"removeall": func(r *Runner) { osRemoveAll = func(string) error { return errBoom } },
		"mkdirall":  func(r *Runner) { osMkdirAll = func(string, os.FileMode) error { return errBoom } },
		"mkdir-home": func(r *Runner) {
			n := 0
			osMkdirAll = func(p string, m os.FileMode) error {
				if n++; n >= 2 {
					return errBoom
				}
				return os.MkdirAll(p, m)
			}
		},
		"fetch":        func(r *Runner) { r.Fetch = func(string, string, int) (string, error) { return "", errBoom } },
		"touch":        func(r *Runner) { r.Touch = func(string) error { return errBoom } },
		"writefile":    func(r *Runner) { osWriteFile = func(string, []byte, os.FileMode) error { return errBoom } },
		"writelibexec": func(r *Runner) { writeLibexec = func(string, bool, string, string, string) error { return errBoom } },
		"run":          func(r *Runner) { r.Run = func(string, []string) error { return errBoom } },
		"rename":       func(r *Runner) { osRename = func(string, string) error { return errBoom } },
		"fixup":        func(r *Runner) { r.FixUp = func(fixup.Options) error { return errBoom } },
		"writebottle":  func(r *Runner) { r.WriteBottle = func(_, _, _, _, _, _ string) (string, error) { return "", errBoom } },
		"resolvedep":   func(r *Runner) { r.ResolveDep = func(string, string) (string, error) { return "", errBoom } },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			tenv(t)
			defer restore()
			r := okRunner("acme.org/tool", tgt)
			mut(r)
			if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err == nil {
				t.Errorf("%s: expected error", name)
			}
		})
	}
}

func TestBuildSourceAndGenerateErrors(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	// bad distributable type → sourceOf error
	r := okRunner("p", tgt)
	rec := okRecipe()
	rec.Distributable = 123
	if _, err := r.Build(rec, "p", "*", tgt, tgt, ""); err == nil {
		t.Error("expected sourceOf error")
	}
	// build script with a bad step → Generate error
	rec2 := okRecipe()
	rec2.Distributable = "https://x/v{{version.raw}}.tgz"
	rec2.Build = map[string]any{"script": []any{map[string]any{"run": 5}}}
	if _, err := r.Build(rec2, "p", "*", tgt, tgt, ""); err == nil {
		t.Error("expected Generate error")
	}
}

func TestSourcesOf(t *testing.T) {
	// a scalar string yields a single candidate
	got, err := sourcesOf("https://x/v{{version.raw}}.tgz", "1.2.3", "v1.2.3")
	if err != nil || len(got) != 1 || got[0].url != "https://x/v1.2.3.tgz" || got[0].git {
		t.Errorf("string dist = %+v %v", got, err)
	}
	// a map yields a single candidate; string strip-components parses
	got, err = sourcesOf(map[string]any{"url": "u-{{version.major}}", "strip-components": "2"}, "3.4.5", "v3.4.5")
	if err != nil || len(got) != 1 || got[0].url != "u-3" || got[0].strip != 2 {
		t.Errorf("map dist = %+v %v", got, err)
	}
	// git via ref + int strip
	got, _ = sourcesOf(map[string]any{"url": "g", "ref": "r{{version.minor}}", "strip-components": 1}, "3.4.5", "v3.4.5")
	if len(got) != 1 || !got[0].git || got[0].ref != "r4" || got[0].strip != 1 {
		t.Errorf("git dist = %+v", got)
	}
	// missing url + unsupported type
	if _, err := sourcesOf(map[string]any{}, "1", "1"); err == nil {
		t.Error("expected missing-url error")
	}
	if _, err := sourcesOf(42, "1", "1"); err == nil {
		t.Error("expected unsupported-type error")
	}
	// list form: EVERY entry is returned, in order — the canonical source first,
	// then fallback mirrors, each keeping its own url + strip-components.
	got, err = sourcesOf([]any{
		map[string]any{"url": "https://up/v{{version.raw}}.tgz", "strip-components": 1},
		map[string]any{"url": "https://mirror/v{{version.raw}}.tgz", "strip-components": 2},
	}, "1.2.3", "v1.2.3")
	if err != nil || len(got) != 2 {
		t.Fatalf("list dist = %+v %v", got, err)
	}
	if got[0].url != "https://up/v1.2.3.tgz" || got[0].strip != 1 {
		t.Errorf("list primary = %+v", got[0])
	}
	if got[1].url != "https://mirror/v1.2.3.tgz" || got[1].strip != 2 {
		t.Errorf("list mirror = %+v", got[1])
	}
	// a bare string entry in a list is equally valid
	if got, _ = sourcesOf([]any{"https://x/v{{version.raw}}.tgz"}, "1.2.3", "v1.2.3"); len(got) != 1 || got[0].url != "https://x/v1.2.3.tgz" {
		t.Errorf("list-of-string dist = %+v", got)
	}
	// an empty list has no candidates → error
	if _, err := sourcesOf([]any{}, "1", "1"); err == nil {
		t.Error("expected empty-list error")
	}
	// a bad entry inside a list surfaces its error
	if _, err := sourcesOf([]any{map[string]any{}}, "1", "1"); err == nil {
		t.Error("expected bad-entry error inside list")
	}
}

// TestSourcesOfVersionTag is the regression proof for the {{version.tag}} bug:
// a GitHub release download URL that interpolates the raw git tag must expand
// to the tag (both the tight and the space-padded moustache form), NOT keep a
// literal {{version.tag}} that 404s at fetch. It also covers the empty-tag
// fallback to the version string.
func TestSourcesOfVersionTag(t *testing.T) {
	// v-prefixed tag, both {{version.tag}} and {{ version.tag }} spellings.
	got, err := sourcesOf("https://gh/o/r/releases/download/{{version.tag}}/{{ version.tag }}.tar.gz", "1.2.3", "v1.2.3")
	if err != nil || len(got) != 1 || got[0].url != "https://gh/o/r/releases/download/v1.2.3/v1.2.3.tar.gz" {
		t.Fatalf("v-tag dist = %+v %v", got, err)
	}
	// a non-"v" upstream tag (e.g. openssl-3.5.0) is preserved verbatim.
	got, err = sourcesOf("https://gh/openssl/openssl/releases/download/{{version.tag}}/openssl-{{version.raw}}.tar.gz", "3.5.0", "openssl-3.5.0")
	if err != nil || len(got) != 1 || got[0].url != "https://gh/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz" {
		t.Fatalf("non-v-tag dist = %+v %v", got, err)
	}
	// empty tag falls back to the version string so the token still expands.
	got, err = sourcesOf("https://x/{{version.tag}}.tgz", "4.5.6", "")
	if err != nil || len(got) != 1 || got[0].url != "https://x/4.5.6.tgz" {
		t.Fatalf("empty-tag fallback dist = %+v %v", got, err)
	}
}

// TestBuildFetchMirrorFallback proves a list-form distributable retries the
// next mirror when an earlier candidate fails, and only fails when all do.
func TestBuildFetchMirrorFallback(t *testing.T) {
	defer func() { logf = origLogf }()
	logf = func(string, ...any) {} // mute the fallback notice
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	project := "acme.org/tool"
	dist := []any{
		map[string]any{"url": "https://primary/v{{version.raw}}.tgz", "strip-components": 1},
		map[string]any{"url": "https://mirror/v{{version.raw}}.tgz", "strip-components": 1},
	}

	// first candidate fails, second succeeds → build proceeds
	t.Run("second-succeeds", func(t *testing.T) {
		tenv(t)
		r := okRunner(project, tgt)
		rec := okRecipe()
		rec.Distributable = dist
		var tried []string
		r.Fetch = func(url, _ string, _ int) (string, error) {
			tried = append(tried, url)
			if strings.Contains(url, "primary") {
				return "", errBoom
			}
			return "d16e57", nil
		}
		res, err := r.Build(rec, project, "*", tgt, tgt, "")
		if err != nil {
			t.Fatalf("fallback build should succeed: %v", err)
		}
		if len(tried) != 2 || !strings.Contains(tried[0], "primary") || !strings.Contains(tried[1], "mirror") {
			t.Errorf("tried order = %v", tried)
		}
		// The candidate that ANSWERED is what gets recorded, not the first one
		// the recipe names: a build that fell through to a mirror and one that
		// did not are different builds, and only this says which happened.
		if !strings.Contains(res.Source.URI, "mirror") || res.Source.SHA256 != "d16e57" {
			t.Errorf("source = %+v, want the mirror that answered", res.Source)
		}
	})

	// every candidate fails → the build fails with a fetch error
	t.Run("all-fail", func(t *testing.T) {
		tenv(t)
		r := okRunner(project, tgt)
		rec := okRecipe()
		rec.Distributable = dist
		r.Fetch = func(string, string, int) (string, error) { return "", errBoom }
		if _, err := r.Build(rec, project, "*", tgt, tgt, ""); err == nil {
			t.Error("expected fetch error when all mirrors fail")
		}
	})
}

// TestBuildStageInstallDestExists drives the dest-exists rename branch with real
// os calls: Run leaves both the +brewing tree AND the final prefix in place, so
// stage-install must remove the stale prefix and then rename successfully.
func TestBuildStageInstallDestExists(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	project := "acme.org/tool"
	r := okRunner(project, tgt)
	r.Run = func(string, []string) error {
		if err := os.MkdirAll(r.BuildInstall, 0o755); err != nil {
			return err
		}
		// a prior/duplicate install already occupies the final hashed prefix
		return os.MkdirAll(r.Install, 0o755)
	}
	res, err := r.Build(okRecipe(), project, "*", tgt, tgt, "")
	if err != nil {
		t.Fatalf("dest-exists rename should succeed: %v", err)
	}
	if _, err := os.Stat(res.Install); err != nil {
		t.Errorf("final prefix missing after stage: %v", err)
	}
}

// TestBuildStageInstallRemoveError covers the dest-exists RemoveAll failure: the
// final prefix reports as present but cannot be removed, so stage-install errors.
func TestBuildStageInstallRemoveError(t *testing.T) {
	tenv(t)
	defer func() { osStat, osRemoveAll = os.Stat, os.RemoveAll }()
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	project := "acme.org/tool"
	r := okRunner(project, tgt)
	// The prefix is learned from the Runner when Run fires rather than
	// recomputed: it carries the build's identity hash. Empty until then,
	// which is also what keeps the seams out of the initial cleanup loop —
	// only the stage-install removal must fail, and that one happens after
	// the build has run.
	var install string
	realRun := r.Run
	r.Run = func(p string, e []string) error { install = r.Install; return realRun(p, e) }
	osStat = func(name string) (os.FileInfo, error) {
		if install != "" && name == install {
			return nil, nil // report the final prefix as present at stage time
		}
		return os.Stat(name)
	}
	osRemoveAll = func(name string) error {
		if install != "" && name == install {
			return errBoom // ...but at stage time it cannot be removed
		}
		return os.RemoveAll(name)
	}
	if _, err := r.Build(okRecipe(), project, "*", tgt, tgt, ""); err == nil {
		t.Error("expected stage-install remove error")
	}
}

// restorePropSeams resets the props-copy os seams after a test mutates them.
func restorePropSeams() {
	osStat, osReadDir, osReadFile = os.Stat, os.ReadDir, os.ReadFile
	osMkdirAll, osWriteFile = os.MkdirAll, os.WriteFile
	copyProps = copyPropsTree
}

func TestBuildCopiesProps(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	project := "acme.org/tool"

	// the recipe dir IS props/: a 0644 patch at its root and an executable helper
	// in a sub-directory, exercising file + nested-dir + mode-preservation paths.
	recipeDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(recipeDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	patch := filepath.Join(recipeDir, "patch.txt")
	if err := os.WriteFile(patch, []byte("the patch"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(patch, 0o644)
	script := filepath.Join(recipeDir, "sub", "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(script, 0o755)

	r := okRunner(project, tgt)
	r.RecipeDir = recipeDir
	rec := okRecipe()
	// a script that references both a relative props path and the {{props}} token
	rec.Build = map[string]any{"script": []any{"patch -p1 < props/patch.txt", "test -f {{props}}/patch.txt"}}
	res, err := r.Build(rec, project, "*", tgt, tgt, "")
	if err != nil {
		t.Fatal(err)
	}

	build := config.Compute(project, "1.2.3", testBuildHash, tgt).Build
	// the patch landed at <build>/props/patch.txt with matching contents + mode
	dstPatch := filepath.Join(build, "props", "patch.txt")
	b, err := os.ReadFile(dstPatch)
	if err != nil || string(b) != "the patch" {
		t.Fatalf("props file = %q %v", b, err)
	}
	if fi, _ := os.Stat(dstPatch); fi.Mode().Perm() != 0o644 {
		t.Errorf("patch mode = %v, want 0644", fi.Mode().Perm())
	}
	// the executable helper preserved its 0755 mode through the copy
	if fi, _ := os.Stat(filepath.Join(build, "props", "sub", "run.sh")); fi == nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("helper mode = %v, want 0755", fi.Mode().Perm())
	}
	// the {{props}} token resolved to the absolute build props dir in the script
	sc, _ := os.ReadFile(res.ScriptPath)
	if want := filepath.Join(build, "props"); !strings.Contains(string(sc), want+"/patch.txt") {
		t.Errorf("script missing resolved {{props}} (%s):\n%s", want, sc)
	}
}

func TestBuildNoProps(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	project := "acme.org/tool"
	// No props copied when RecipeDir is unset (the != "" guard) or points at a
	// path that does not exist (the osStat guard). Both build fine, no props/.
	for _, rd := range []string{"", filepath.Join(t.TempDir(), "nope")} {
		r := okRunner(project, tgt)
		r.RecipeDir = rd
		if _, err := r.Build(okRecipe(), project, "*", tgt, tgt, ""); err != nil {
			t.Fatalf("RecipeDir=%q: %v", rd, err)
		}
		if _, err := os.Stat(filepath.Join(config.Compute(project, "1.2.3", testBuildHash, tgt).Build, "props")); !os.IsNotExist(err) {
			t.Errorf("RecipeDir=%q: props dir should not exist: %v", rd, err)
		}
	}
}

func TestBuildPropsCopyError(t *testing.T) {
	tenv(t)
	defer restorePropSeams()
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	recipeDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(recipeDir, "props"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyProps = func(string, string) error { return errBoom }
	r := okRunner("acme.org/tool", tgt)
	r.RecipeDir = recipeDir
	if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, ""); err == nil {
		t.Error("expected copy-props error")
	}
}

func TestCopyPropsTree(t *testing.T) {
	defer restorePropSeams()

	// happy path is covered by TestBuildCopiesProps; here we drive every internal
	// error branch by making one os seam fail at a time.
	mksrc := func(t *testing.T) string {
		d := t.TempDir()
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}

	t.Run("stat-src", func(t *testing.T) {
		defer restorePropSeams()
		osStat = func(string) (os.FileInfo, error) { return nil, errBoom }
		if err := copyPropsTree("s", "d"); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("mkdir-root", func(t *testing.T) {
		defer restorePropSeams()
		osMkdirAll = func(string, os.FileMode) error { return errBoom }
		if err := copyPropsTree(mksrc(t), filepath.Join(t.TempDir(), "out")); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("readdir", func(t *testing.T) {
		defer restorePropSeams()
		osReadDir = func(string) ([]os.DirEntry, error) { return nil, errBoom }
		if err := copyPropsTree(mksrc(t), filepath.Join(t.TempDir(), "out")); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("recurse", func(t *testing.T) {
		defer restorePropSeams()
		n := 0
		osMkdirAll = func(p string, m os.FileMode) error {
			if n++; n >= 2 { // fail the nested sub/ dir, not the root
				return errBoom
			}
			return os.MkdirAll(p, m)
		}
		if err := copyPropsTree(mksrc(t), filepath.Join(t.TempDir(), "out")); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("stat-file", func(t *testing.T) {
		defer restorePropSeams()
		n := 0
		osStat = func(p string) (os.FileInfo, error) {
			if n++; n >= 2 { // src ok, first file stat fails
				return nil, errBoom
			}
			return os.Stat(p)
		}
		if err := copyPropsTree(mksrc(t), filepath.Join(t.TempDir(), "out")); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("readfile", func(t *testing.T) {
		defer restorePropSeams()
		osReadFile = func(string) ([]byte, error) { return nil, errBoom }
		if err := copyPropsTree(mksrc(t), filepath.Join(t.TempDir(), "out")); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("writefile", func(t *testing.T) {
		defer restorePropSeams()
		osWriteFile = func(string, []byte, os.FileMode) error { return errBoom }
		if err := copyPropsTree(mksrc(t), filepath.Join(t.TempDir(), "out")); err != errBoom {
			t.Errorf("err = %v", err)
		}
	})
}

func TestHelpers(t *testing.T) {
	if (&Runner{Concurrency: 3}).concurrency() != 3 {
		t.Error("explicit concurrency")
	}
	if (&Runner{}).concurrency() < 1 {
		t.Error("default concurrency")
	}
	if buildDeps(&pantry.Recipe{Build: "just a string"}) != nil {
		t.Error("non-map build → nil deps")
	}
	if str(5) != "" || str("x") != "x" {
		t.Error("str helper")
	}
}

// TestVerifyDeclaredChecksum covers the one thing this check exists for: bytes
// that are not the bytes the upstream says it published.
func TestVerifyDeclaredChecksum(t *testing.T) {
	tgt := target.Host()
	const digest = "b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9"
	dist := map[string]any{"url": "https://x/v{{version.raw}}.tgz", "sha": "${{url}}.sha256"}

	newRunner := func(project string, got string) (*Runner, *[]string) {
		r := okRunner(project, tgt)
		asked := &[]string{}
		r.Fetch = func(string, string, int) (string, error) { return got, nil }
		r.FetchSHA = func(shaURL, archive string) (string, error) {
			*asked = append(*asked, shaURL+" for "+archive)
			return digest, nil
		}
		return r, asked
	}

	t.Run("match", func(t *testing.T) {
		tenv(t)
		r, asked := newRunner("m/p", digest)
		rec := okRecipe()
		rec.Distributable = dist
		if _, err := r.Build(rec, "m/p", "*", tgt, tgt, ""); err != nil {
			t.Fatalf("build: %v", err)
		}
		// `${{url}}` resolves against THIS entry's url, and the archive name is
		// handed over so a multi-file SHA256SUMS can be matched on it.
		if len(*asked) != 1 || (*asked)[0] != "https://x/v1.2.3.tgz.sha256 for https://x/v1.2.3.tgz" {
			t.Errorf("asked = %v", *asked)
		}
	})

	t.Run("mismatch fails the build", func(t *testing.T) {
		tenv(t)
		r, _ := newRunner("x/p", "0000000000000000000000000000000000000000000000000000000000000000")
		rec := okRecipe()
		rec.Distributable = dist
		_, err := r.Build(rec, "x/p", "*", tgt, tgt, "")
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("err = %v; want ErrChecksumMismatch", err)
		}
		// The message must carry BOTH digests: "checksum mismatch" alone sends
		// the reader back to re-download by hand to learn what arrived.
		if !strings.Contains(err.Error(), digest) || !strings.Contains(err.Error(), "0000000000") {
			t.Errorf("message hides one side: %v", err)
		}
	})

	// A mismatch must NOT fall through to the next mirror. A build that quietly
	// succeeded from a second host after the first served unexpected bytes is a
	// build that hid the one event this check exists to surface.
	t.Run("mismatch does not try the next mirror", func(t *testing.T) {
		tenv(t)
		r := okRunner("f/p", tgt)
		var tried []string
		r.Fetch = func(url string, _ string, _ int) (string, error) {
			tried = append(tried, url)
			return "0000000000000000000000000000000000000000000000000000000000000000", nil
		}
		r.FetchSHA = func(string, string) (string, error) { return digest, nil }
		rec := okRecipe()
		rec.Distributable = []any{
			map[string]any{"url": "https://primary/v{{version.raw}}.tgz", "sha": "${{url}}.sha256"},
			map[string]any{"url": "https://mirror/v{{version.raw}}.tgz"},
		}
		if _, err := r.Build(rec, "f/p", "*", tgt, tgt, ""); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("err = %v", err)
		}
		if len(tried) != 1 {
			t.Errorf("tried %v; the mirror must not be reached after a mismatch", tried)
		}
	})

	// "The checksum file was unavailable, so we built anyway" is the reasoning
	// that leaves a verification permanently disarmed.
	t.Run("unfetchable checksum fails too", func(t *testing.T) {
		tenv(t)
		r, _ := newRunner("u/p", digest)
		r.FetchSHA = func(string, string) (string, error) { return "", errBoom }
		rec := okRecipe()
		rec.Distributable = dist
		if _, err := r.Build(rec, "u/p", "*", tgt, tgt, ""); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v; want the fetch-sha failure", err)
		}
	})

	t.Run("skipped where it cannot apply", func(t *testing.T) {
		for _, c := range []struct {
			name string
			prep func(*Runner, *pantry.Recipe)
		}{
			// 1857 of 1858 recipes declare no sha; failing them would ship nothing.
			{"no sha declared", func(r *Runner, rec *pantry.Recipe) {
				rec.Distributable = map[string]any{"url": "https://x/v{{version.raw}}.tgz"}
			}},
			// A checkout has a commit, not a hash of bytes.
			{"git source", func(r *Runner, rec *pantry.Recipe) {
				rec.Distributable = map[string]any{"url": "https://git/r", "ref": "v{{version.raw}}", "sha": "${{url}}.sha256"}
			}},
			// No verifier wired: a caller that does not want the network.
			{"no FetchSHA", func(r *Runner, rec *pantry.Recipe) {
				rec.Distributable = dist
				r.FetchSHA = nil
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				tenv(t)
				r, _ := newRunner("s/p", "0000000000000000000000000000000000000000000000000000000000000000")
				r.FetchGit = func(string, string, string) (string, error) { return "cafe", nil }
				rec := okRecipe()
				c.prep(r, rec)
				if _, err := r.Build(rec, "s/p", "*", tgt, tgt, ""); err != nil {
					t.Errorf("build: %v", err)
				}
			})
		}
	})
}

// TestBuildBootstrapOmitsTheToolchainFromTheSCRIPT.
//
// The point of the flag is what the build RUNS, and that is the generated
// script, not a function's return value. A field wired to nothing would pass a
// test of BootstrapToolDeps and change no build at all -- so this reads the
// script bk actually writes, both ways, from one recipe.
func TestBuildBootstrapOmitsTheToolchainFromTheScript(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	read := func(t *testing.T, boot bool) string {
		tenv(t)
		r := okRunner("acme.org/tool", tgt)
		r.Bootstrap = boot
		res, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(res.ScriptPath)
		return string(b)
	}

	ordinary := read(t, false)
	if !strings.Contains(ordinary, `"+gnu.org/autoconf"`) {
		t.Fatalf("premise wrong: an ordinary build no longer carries the toolchain:\n%s", ordinary)
	}

	boot := read(t, true)
	if strings.Contains(boot, `"+gnu.org/autoconf"`) {
		t.Errorf("bootstrap must not inject the base toolchain:\n%s", boot)
	}
	// What the recipe declares for itself is NOT the toolchain and must stay:
	// the seed still links against real bottles, only the tools driving the
	// build come from the host.
	if !strings.Contains(boot, `"+freedesktop.org/pkg-config^0.29"`) {
		t.Errorf("bootstrap dropped the recipe's OWN build dependency:\n%s", boot)
	}
	if !strings.Contains(boot, `"+openssl.org^1.1"`) {
		t.Errorf("bootstrap must not touch the LINK closure:\n%s", boot)
	}
	// And the compiler, which is injected separately from the toolchain and was
	// the next wall --bootstrap hit: pkgx +llvm.org against a registry that has
	// no s390x, and an upstream that has none either.
	if !strings.Contains(ordinary, `"+llvm.org"`) {
		t.Fatalf("premise wrong: an ordinary linux build no longer adds llvm.org:\n%s", ordinary)
	}
	if strings.Contains(boot, `"+llvm.org"`) {
		t.Errorf("bootstrap must take the compiler from the host too:\n%s", boot)
	}
}

// TestBuildBootstrapDropsTheSelfEdge: end to end, because the point is what
// the build asks pkgx for, not what a helper returns.
func TestBuildBootstrapDropsTheSelfEdge(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	// The gcc shape: a build dependency on itself, beside an ordinary one.
	rec.Build = map[string]any{
		"script": []any{"make install"},
		"dependencies": map[string]any{
			"acme.org/tool": ">=14",
			"gnu.org/make":  "*",
		},
	}
	r := okRunner("acme.org/tool", tgt)
	r.Bootstrap = true
	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	s := string(b)
	if strings.Contains(s, `"+acme.org/tool`) {
		t.Errorf("a build must not be handed a bottle of itself here:\n%s", s)
	}
	if !strings.Contains(s, `"+gnu.org/make"`) {
		t.Errorf("the other build dependency must survive:\n%s", s)
	}
}

// TestBuildBootstrapRefusesAnUnresolvedDepToken.
//
// gnu.org/sed builds with {{deps.gnu.org/sed.prefix}}. Dropping its self edge
// leaves that token unsubstituted, and a literal {{deps.…}} reaching the shell
// fails somewhere that names neither sed nor bootstrap. Refusing here names
// both.
func TestBuildBootstrapRefusesAnUnresolvedDepToken(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	rec.Build = map[string]any{
		"script":       []any{"{{deps.acme.org/tool.prefix}}/bin/tool --version"},
		"dependencies": map[string]any{"acme.org/tool": ">=14"},
	}
	r := okRunner("acme.org/tool", tgt)
	r.Bootstrap = true
	_, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err == nil {
		t.Fatal("want a refusal naming the project")
	}
	if !strings.Contains(err.Error(), "acme.org/tool") || !strings.Contains(err.Error(), "bootstrap") {
		t.Errorf("err = %v; want it to name the project and the mode", err)
	}
	// And the same recipe builds fine in the ORDINARY mode, where the bottle of
	// its dependency is expected to exist.
	r2 := okRunner("acme.org/tool", tgt)
	if _, err := r2.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err != nil {
		t.Errorf("the refusal must be bootstrap-only, got %v", err)
	}
}

// TestBuildBootstrapLeavesAnUnresolvableToolToTheHost, end to end and both
// ways: the tool must be absent from the script a seed build runs, and an
// ORDINARY build must still fail on it, because there the missing bottle is a
// real gap rather than something the machine can cover.
func TestBuildBootstrapLeavesAnUnresolvableToolToTheHost(t *testing.T) {
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	rec.Build = map[string]any{
		"script": []any{"make install"},
		// The ca-certs shape: a tool used to FETCH, plus one we do have.
		"dependencies": map[string]any{"curl.se": "*", "gnu.org/make": "*"},
	}
	mk := func(boot bool) *Runner {
		r := okRunner("acme.org/tool", tgt)
		r.Bootstrap = boot
		r.ResolveDep = func(p, _ string) (string, error) {
			if p == "curl.se" {
				return "", errors.New("no bottle for linux/s390x")
			}
			return "1.0.0", nil
		}
		return r
	}

	tenv(t)
	res, err := mk(true).Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatalf("bootstrap build = %v", err)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	s := string(b)
	if strings.Contains(s, `"+curl.se`) {
		t.Errorf("an unresolvable tool must be left to the host:\n%s", s)
	}
	if !strings.Contains(s, `"+gnu.org/make"`) {
		t.Errorf("a tool the registry HAS must stay a bottle:\n%s", s)
	}

	tenv(t)
	if _, err := mk(false).Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err == nil {
		t.Error("an ordinary build must still fail on a tool with no bottle")
	}
}

// TestBuildBootstrapFailureNamesWhatCameFromTheHost.
//
// Twice a seed build died with `exit status 127` — command not found —
// because a tool bootstrap left to the machine was not on the machine either:
// facebook.com/zstd wanted cmake and ninja, and that Ubuntu had neither.
//
// The drop IS logged when it happens. By the time the failure prints, that
// line is hundreds of lines back and half the time belongs to another recipe,
// so the two have to be read together at the point of failure.
func TestBuildBootstrapFailureNamesWhatCameFromTheHost(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	rec.Build = map[string]any{
		"script":       []any{"cmake ."},
		"dependencies": map[string]any{"cmake.org": "*", "ninja-build.org": "*", "gnu.org/make": "*"},
	}
	r := okRunner("acme.org/tool", tgt)
	r.Bootstrap = true
	// Only the two TOOLS are missing. The recipe's link dependency must still
	// resolve — a bootstrap never touches the link closure, and a stub that
	// failed it too would make this test pass for the wrong reason.
	r.ResolveDep = func(p, _ string) (string, error) {
		if p == "cmake.org" || p == "ninja-build.org" {
			return "", errors.New("no bottle for linux/s390x")
		}
		return "1.0.0", nil
	}
	r.Run = func(string, []string) error { return errors.New("exit status 127") }

	_, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err == nil {
		t.Fatal("want the build to fail")
	}
	for _, want := range []string{"127", "cmake.org", "ninja-build.org"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must carry %q: %v", want, err)
		}
	}
	// A tool that RESOLVED is not a suspect and must not be listed — a list
	// naming everything names nothing.
	if strings.Contains(err.Error(), "gnu.org/make") {
		t.Errorf("a resolved dependency must not be blamed: %v", err)
	}
}

// And an ORDINARY build's failure gains nothing: there is no host substitution
// to explain, and the extra clause would be noise on every real defect.
func TestBuildOrdinaryFailureIsUnchanged(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)
	r.Run = func(string, []string) error { return errors.New("exit status 1") }
	_, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err == nil || strings.Contains(err.Error(), "from the host") {
		t.Errorf("an ordinary failure must stay plain: %v", err)
	}
}

// TestBuildBootstrapTakesItsOwnPrefixFromTheHost.
//
// The other half of the refusal above. gnu.org/sed build-depends on itself for
// one line — it puts a known-good sed in front of whatever the system has —
// and on an architecture with no sed bottle the system's IS the only sed. The
// recipe says it provides bin/sed and the host says sed is at /usr/bin/sed, so
// /usr is the prefix that makes both statements true.
//
// End to end, and asserting on the SCRIPT: a helper returning the right token
// says nothing about whether the build received it.
func TestBuildBootstrapTakesItsOwnPrefixFromTheHost(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	recipe := func() *pantry.Recipe {
		rec := okRecipe()
		rec.Provides = []any{"bin/tool"}
		rec.Build = map[string]any{
			"script":       []any{`export PATH="{{deps.acme.org/tool.prefix}}/bin:$PATH"`},
			"dependencies": map[string]any{"acme.org/tool": ">=14"},
		}
		return rec
	}

	r := okRunner("acme.org/tool", tgt)
	r.Bootstrap = true
	r.LookPath = func(name string) (string, error) {
		if name == "tool" {
			return "/usr/bin/tool", nil
		}
		return "", errors.New("not found")
	}
	res, err := r.Build(recipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatalf("the host provides it, so the build must proceed: %v", err)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	if s := string(b); !strings.Contains(s, `export PATH="/usr/bin:$PATH"`) {
		t.Errorf("want the host's prefix in the script:\n%s", s)
	}

	// The host does NOT have it: no prefix is invented, and the build refuses
	// exactly as it did before. A guessed path would send a compiler somewhere
	// nobody chose.
	r2 := okRunner("acme.org/tool", tgt)
	r2.Bootstrap = true
	r2.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	if _, err := r2.Build(recipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err == nil {
		t.Error("with nothing on the host to confirm it, the build must still refuse")
	}

	// And NOT in the ordinary mode: there the bottle exists, nothing was
	// dropped, and the recipe's own prefix must come from the registry rather
	// than from whatever the build machine happens to have installed.
	r3 := okRunner("acme.org/tool", tgt)
	r3.LookPath = func(string) (string, error) { return "/usr/bin/tool", nil }
	res3, err := r3.Build(recipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(res3.ScriptPath); strings.Contains(string(b), `"/usr/bin:$PATH"`) {
		t.Errorf("an ordinary build must not take a prefix from the host:\n%s", b)
	}
}

// TestBuildBootstrapDropsAToolWhoseClosureIsNotHere.
//
// ResolveDep says perl.org is here; ToolInstallable says installing it is
// another matter. Bootstrap must believe the second, because a tool it cannot
// install is a tool it does not have — the build otherwise dies in `pkgx
// +perl.org` with a 404 for the project it is building.
func TestBuildBootstrapDropsAToolWhoseClosureIsNotHere(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "s390x"}
	rec := okRecipe()
	rec.Build = map[string]any{
		"script":       []any{"make install"},
		"dependencies": map[string]any{"perl.org": "*", "gnu.org/make": "*"},
	}

	var log strings.Builder
	r := okRunner("acme.org/tool", tgt)
	r.Bootstrap = true
	// The weaker question answers yes for everything, as it did in the seed.
	r.ResolveDep = func(string, string) (string, error) { return "1.0.0", nil }
	r.ToolInstallable = func(project, _ string) (string, error) {
		if project == "perl.org" {
			return "", errors.New("perl.org 5.44.0 is here but its closure is not")
		}
		return "1.0.0", nil
	}
	oldLog := logf
	logf = func(f string, a ...any) { fmt.Fprintf(&log, f+"\n", a...) }
	t.Cleanup(func() { logf = oldLog })

	res, err := r.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	s := string(b)
	if strings.Contains(s, `"+perl.org"`) {
		t.Errorf("a tool that cannot be installed must not be asked for:\n%s", s)
	}
	if !strings.Contains(s, `"+gnu.org/make"`) {
		t.Errorf("the installable tool must survive:\n%s", s)
	}
	// Reported, not silent, and saying it is not ABSENT: perl.org was there.
	if !strings.Contains(log.String(), "cannot install perl.org here") {
		t.Errorf("the drop must be reported and say what it means: %q", log.String())
	}

	// With no ToolInstallable wired, the weaker question decides and nothing is
	// dropped — a Runner that does not know how to ask keeps its old behaviour.
	r2 := okRunner("acme.org/tool", tgt)
	r2.Bootstrap = true
	r2.ResolveDep = func(string, string) (string, error) { return "1.0.0", nil }
	res2, err := r2.Build(rec, "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(res2.ScriptPath); !strings.Contains(string(b), `"+perl.org"`) {
		t.Errorf("without the stronger question, nothing changes:\n%s", b)
	}
}

// A recipe with no distributable fetches nothing, which is legitimate — and
// leaves the build directory EMPTY. The first step that reaches for a file in
// it then fails with the least informative error the kernel has:
//
//	fork/exec …/build/configure: no such file or directory
//
// which reads as "the script is missing" and sends its reader to the tarball,
// the extractor and the shebang, all of which are fine. Say it up front.
func TestRunnerSaysWhenARecipeDeclaresNoSource(t *testing.T) {
	var lines []string
	logf = func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { logf = origLogf })

	tgt := target.Target{Platform: "linux", Arch: "x86-64", Triple: "x86_64-linux-gnu"}
	r := okRunner("acme.org/tool", tgt)
	rec := okRecipe()
	rec.Distributable = nil

	_, _ = r.Build(rec, "acme.org/tool", "*", tgt, tgt, "")

	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "declares no distributable") {
		t.Errorf("nothing said about the empty build dir:\n%s", joined)
	}
	if !strings.Contains(joined, "stays empty") {
		t.Errorf("the message states the fact and not the consequence:\n%s", joined)
	}

	// And a recipe that DOES fetch says nothing: a line printed every time is
	// a line nobody reads.
	lines = nil
	_, _ = r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, "")
	if strings.Contains(strings.Join(lines, "\n"), "declares no distributable") {
		t.Errorf("the notice fired for a recipe with a source:\n%s", strings.Join(lines, "\n"))
	}
}

// The gen1 message was `run: fork/exec …/build/configure: no such file or
// directory` and nothing else, and two very different stories fit it: the
// directory is empty, so the source never landed; or the source landed and
// configure sits one level down, which is a strip-components fault. The class
// stayed open for a day because the log separated neither.
func TestBuildDirListingSeparatesEmptyFromMisplaced(t *testing.T) {
	dir := t.TempDir()
	cause := fmt.Errorf("fork/exec %s/configure: no such file or directory", dir)

	// Empty says so in those words: it is the most informative thing here.
	if got := buildDirListing(dir, cause); !strings.Contains(got, "is EMPTY — the source never landed there") {
		t.Errorf("empty directory: %q", got)
	}

	// One level down is the other story, and the listing shows it.
	if err := os.MkdirAll(filepath.Join(dir, "bash-5.3"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := buildDirListing(dir, cause)
	if !strings.Contains(got, "holds 1 entry: bash-5.3/") {
		t.Errorf("one subdirectory: %q", got)
	}
	// "1 entries" is a line nobody trusts again.
	if strings.Contains(got, "1 entries") {
		t.Errorf("mis-pluralised: %q", got)
	}
}

// A compiler error or a failing test has nothing to do with the build
// directory, and a diagnostic printed for every failure is one readers skip.
func TestBuildDirListingStaysQuietForAnUnrelatedFailure(t *testing.T) {
	dir := t.TempDir()
	for _, cause := range []error{
		errors.New("exit status 1"),
		errors.New("make: *** [all] Error 2"),
		nil,
	} {
		if got := buildDirListing(dir, cause); got != "" {
			t.Errorf("listing attached to %v: %q", cause, got)
		}
	}
	if got := buildDirListing("", fmt.Errorf("anything")); got != "" {
		t.Errorf("listing with no directory: %q", got)
	}
}

func TestBuildDirListingTruncatesAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := buildDirListing(dir, fmt.Errorf("fork/exec %s/configure: nope", dir))
	if !strings.Contains(got, "holds 20 entries") || !strings.Contains(got, "and 8 more") {
		t.Errorf("truncation: %q", got)
	}
}

// A directory that cannot be read and one that is empty are different facts,
// and telling them apart is the whole point of the line.
func TestCountEntriesDistinguishesUnreadableFromEmpty(t *testing.T) {
	dir := t.TempDir()
	if got := countEntries(dir); got != 0 {
		t.Errorf("empty = %d; want 0", got)
	}
	if got := countEntries(filepath.Join(dir, "nope")); got != -1 {
		t.Errorf("absent = %d; want -1", got)
	}
	if got := plural(-1, "entry", "entries"); !strings.Contains(got, "unreadable") {
		t.Errorf("plural(-1) = %q", got)
	}
	if got := plural(1, "entry", "entries"); got != "1 entry" {
		t.Errorf("plural(1) = %q", got)
	}
	if got := plural(3, "entry", "entries"); got != "3 entries" {
		t.Errorf("plural(3) = %q", got)
	}
}

// The listing must survive a directory it cannot read, and say which.
func TestBuildDirListingReportsAnUnreadableDirectory(t *testing.T) {
	prev := osReadDir
	osReadDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("permission denied") }
	defer func() { osReadDir = prev }()
	got := buildDirListing("/d", fmt.Errorf("fork/exec /d/configure: nope"))
	if !strings.Contains(got, "could not be read: permission denied") {
		t.Errorf("unreadable: %q", got)
	}
}

// The fetch line exists because its ABSENCE cost a day: with nothing logged,
// a successful build and one whose source never landed were indistinguishable
// at exactly the point that mattered. A line nobody asserts is a line that
// can quietly change or go away again, so this pins its content.
func TestBuildSaysWhatItFetchedAndHowMuchArrived(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)

	// A fetch that puts two things in the build directory, as a real one does.
	r.Fetch = func(_, dest string, _ int) (string, error) {
		for _, n := range []string{"configure", "Makefile.in"} {
			if err := os.WriteFile(filepath.Join(dest, n), nil, 0o644); err != nil {
				return "", err
			}
		}
		return "deadbeef", nil
	}

	var log strings.Builder
	oldLog := logf
	logf = func(f string, a ...any) { fmt.Fprintf(&log, f+"\n", a...) }
	t.Cleanup(func() { logf = oldLog })

	if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err != nil {
		t.Fatal(err)
	}
	got := log.String()
	// The URL, so a build that fell through to a mirror is distinguishable
	// from one that did not; and the COUNT, which is what separates "the
	// source landed" from "the directory is empty".
	for _, want := range []string{"fetched https://x/v1.2.3.tar.gz", "2 entries"} {
		if !strings.Contains(got, want) {
			t.Errorf("the fetch line does not say %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "2 entry") {
		t.Errorf("mis-pluralised:\n%s", got)
	}
}

// A fetch that lands nothing says so, which is the case four gen1 packages
// needed and nobody could see.
func TestBuildSaysWhenAFetchLandedNothing(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)
	r.Fetch = func(string, string, int) (string, error) { return "cafe", nil } // writes nothing

	var log strings.Builder
	oldLog := logf
	logf = func(f string, a ...any) { fmt.Fprintf(&log, f+"\n", a...) }
	t.Cleanup(func() { logf = oldLog })

	if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err != nil {
		t.Fatal(err)
	}
	if got := log.String(); !strings.Contains(got, "0 entries") {
		t.Errorf("an empty fetch did not say so:\n%s", got)
	}
}

// The listing printed twelve names and `configure` sorts after every capital
// letter in ASCII, so for gnu.org/bash it fell into "… and 115 more" — the
// one thing worth knowing was the one thing not shown. Measured on the gen1
// pilot of 2026-10-05: 127 entries listed, the question still open.
func TestBuildDirListingSaysWhetherTheNamedFileIsActuallyThere(t *testing.T) {
	dir := t.TempDir()
	cause := fmt.Errorf("fork/exec %s/configure: no such file or directory", filepath.Join(dir))

	// Present: say so, and say the exec failed for another reason — the two
	// that remain are an interpreter and a loader.
	if err := os.WriteFile(filepath.Join(dir, "configure"), []byte("#! /bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Enough other files that `configure` would be truncated away.
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("A%02d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := buildDirListing(dir, cause)
	if !strings.Contains(got, "configure IS there") {
		t.Errorf("a present file was not reported as present: %q", got)
	}
	for _, w := range []string{"an interpreter its #! names", "loader is absent"} {
		if !strings.Contains(got, w) {
			t.Errorf("the remaining explanations are not named: %q", got)
		}
	}

	// Absent: fall through to the listing, which is the other half.
	if err := os.Remove(filepath.Join(dir, "configure")); err != nil {
		t.Fatal(err)
	}
	if got := buildDirListing(dir, cause); strings.Contains(got, "IS there") || !strings.Contains(got, "holds 20 entries") {
		t.Errorf("an absent file was not reported by the listing: %q", got)
	}
}

// missingName must not guess. A deeper path is a different question, and a
// wrong answer inside an error message is worse than no answer.
func TestMissingNameTakesOnlyADirectChild(t *testing.T) {
	dir := "/b"
	for _, tc := range []struct{ msg, want string }{
		{"fork/exec /b/configure: no such file or directory", "configure"},
		{"fork/exec /b/sub/configure: no such file or directory", ""},
		{"exit status 1", ""},
		{"fork/exec /other/configure: nope", ""},
		{"something about /b/ and nothing after", ""},
	} {
		if got := missingName(errors.New(tc.msg), dir); got != tc.want {
			t.Errorf("missingName(%q) = %q; want %q", tc.msg, got, tc.want)
		}
	}
}

// Building a package must not remove the version of it that is already
// installed, because the rootfs the build runs in may BE that install.
//
// In the sovereign generation /bin/sh is a symlink to
// $ZPKG_DIR/gnu.org/bash/v<ver>/bin/bash — a symlink and not a copy, because
// $ORIGIN in bash's RUNPATH has to resolve from the real location. So
// removing the prefix up front deleted the shell before a line ran, and the
// first `#!/bin/sh` script to be exec'd failed with
//
//	fork/exec …/configure: no such file or directory
//
// naming the script, which exists, rather than the interpreter, which did
// not. Measured on the 78-package s390x generation: gnu.org/bash is built
// 74th and all five packages after it fail; the 73 before it are untouched.
// And bash ALONE fails the same way, which is what rules out composition.
func TestBuildDoesNotRemoveTheInstalledPrefixBeforeBuilding(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	install := seedInstall(t, "acme.org/tool", tgt)

	// What the rootfs is using while the build runs — bash's bin/bash, in the
	// real case.
	if err := os.MkdirAll(filepath.Join(install, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	inUse := filepath.Join(install, "bin", "sh")
	if err := os.WriteFile(inUse, []byte("the shell the rootfs runs on"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := okRunner("acme.org/tool", tgt)
	// A build that FAILS: the installed tree must survive it untouched. This
	// is the case that matters — a failed rebuild destroying a working
	// install is bad on its own, and here it took the whole rootfs with it.
	r.Run = func(string, []string) error { return errors.New("configure: boom") }

	if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err == nil {
		t.Fatal("Build: nil; want the failure the stub raises")
	}
	if _, err := os.Stat(inUse); err != nil {
		t.Fatalf("the installed prefix was removed before the build: %v", err)
	}

	// And a build that SUCCEEDS still replaces it — the rename at the end
	// removes the destination itself, which is why the up-front removal was
	// redundant as well as destructive.
	r2 := okRunner("acme.org/tool", tgt)
	if _, err := r2.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := os.Stat(inUse); err == nil {
		t.Error("a successful build left the OLD install in place; the rename must replace it")
	}
}

// The sibling window: a rename that FAILS must leave the working install
// where it was. Two syscalls is short, but a rootfs whose /bin/sh symlink
// points into a prefix that no longer exists cannot run the next build or
// report why — and a failed rename would leave it that way for good.
func TestAFailedStageLeavesTheWorkingInstallInPlace(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	install := seedInstall(t, "acme.org/tool", tgt)
	if err := os.MkdirAll(filepath.Join(install, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	inUse := filepath.Join(install, "bin", "sh")
	if err := os.WriteFile(inUse, []byte("the working install"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldRename := osRename
	// Refuse exactly the forward rename, discriminating on the SOURCE. An
	// earlier version of this stub keyed on the destination and refused the
	// rollback too — which made the test fail for its own reason and would
	// have read as the code being wrong.
	osRename = func(from, to string) error {
		if from == install+"+brewing" {
			return errors.New("no space left on device")
		}
		return oldRename(from, to)
	}
	t.Cleanup(func() { osRename = oldRename })

	r := okRunner("acme.org/tool", tgt)
	if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist")); err == nil {
		t.Fatal("Build: nil; want the rename failure")
	}
	b, err := os.ReadFile(inUse)
	if err != nil {
		t.Fatalf("the working install did not come back: %v", err)
	}
	if string(b) != "the working install" {
		t.Errorf("what came back is not what was there: %q", b)
	}
}

// Dropping the replaced prefix must be REPORTED, not swallowed. The new tree
// is already in place when this runs, so the build is sound — but a
// `.replacing` directory left behind is a whole duplicate install's worth of
// disk, once per rebuild, and the next failure would name a different
// project.
func TestAFailureToDropTheReplacedPrefixIsReported(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	seedInstall(t, "acme.org/tool", tgt)
	oldRemove := osRemoveAll
	osRemoveAll = func(p string) error {
		if strings.HasSuffix(p, ".replacing") {
			// The pre-emptive clean at the top must still succeed; only the
			// drop AFTER the swap fails, which is why this keys on the tree
			// existing.
			if _, err := os.Stat(p); err == nil {
				return errors.New("device or resource busy")
			}
		}
		return oldRemove(p)
	}
	t.Cleanup(func() { osRemoveAll = oldRemove })

	r := okRunner("acme.org/tool", tgt)
	_, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, filepath.Join(t.TempDir(), "dist"))
	if err == nil || !strings.Contains(err.Error(), "drop the replaced prefix") {
		t.Fatalf("Build: %v; want the drop named", err)
	}
}

// TestBuildExportsThePrefixMapOfTheRealRoot: the script carries a map derived
// from the root the build actually uses (go-zpkg/bk#387).
func TestBuildExportsThePrefixMapOfTheRealRoot(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)
	res, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(res.ScriptPath)
	want := "export ZPKB_FILE_PREFIX_MAP=\"" + config.Compute("acme.org/tool", "1.2.3", testBuildHash, tgt).Root + "=/build\"\n"
	if !strings.Contains(string(b), want) {
		t.Errorf("script lacks %q:\n%s", want, b)
	}
}

// TestBuildRefusesAMapThatCouldNotMatch: a cache root that is not absolute
// would make -ffile-prefix-map a silent no-op, so the build fails instead.
func TestBuildRefusesAMapThatCouldNotMatch(t *testing.T) {
	tenv(t)
	t.Chdir(t.TempDir())
	t.Setenv("XDG_DATA_HOME", "relative-data")
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	r := okRunner("acme.org/tool", tgt)
	if _, err := r.Build(okRecipe(), "acme.org/tool", "*", tgt, tgt, ""); err == nil || !strings.Contains(err.Error(), "prefix map") {
		t.Fatalf("err = %v, want a prefix map refusal", err)
	}
}
