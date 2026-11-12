package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/build"
	"github.com/go-zpkg/zbk/fixup"
	"mvdan.cc/sh/v3/interp"
)

const miniRecipe = "distributable: https://x/v{{version.raw}}.tgz\nbuild:\n  script:\n    - make\ntest: \"true\"\n"

func writeRecipe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "package.yml")
	if err := os.WriteFile(p, []byte(miniRecipe), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// stubFactory returns a factory whose Runner succeeds; its Run creates the
// +brewing dir so the pipeline's rename works. version is fixed to 1.0.0.
//
// ⛔ IT READS THE PREFIX FROM THE RUNNER RATHER THAN COMPUTING IT. The
// install prefix carries the build's identity hash, which depends on the
// recipe and the resolved closure — neither of which this stub has. A real
// script learns the prefix because moustache substituted it in; a stub
// learns it from `r.BuildInstall`, set before Run is called. Recomputing it
// here would be a second definition of the identity, free to drift from the
// first — which is also why it no longer takes a project: it has nothing left
// to key on one.
func stubFactory() func(string) *build.Runner {
	return func(string) *build.Runner {
		r := &build.Runner{
			PickVersion:    func(string, string) (string, error) { return "1.0.0", nil },
			ResolveVersion: func(any, string) (string, string, error) { return "1.0.0", "v1.0.0", nil },
			Fetch:          func(string, string, int) (string, error) { return "b0b0feed", nil },
			FetchGit:       func(string, string, string) (string, error) { return "", nil },
			Touch:          func(string) error { return nil },
			FixUp:          func(fixup.Options) error { return nil },
			WriteBottle:    func(_, _, _, _, _, out string) (string, error) { return filepath.Join(out, "b.tgz"), nil },
		}
		r.Run = func(string, []string) error { return os.MkdirAll(r.BuildInstall, 0o755) }
		return r
	}
}

func tempEnv(t *testing.T) {
	t.Setenv("ZPKG_DIR", filepath.Join(t.TempDir(), "pkgx"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "data"))
	t.Setenv("ZPKG_PANTRY_DIR", "")
	t.Setenv("ZBK_TARGET", "")
}

func TestBuildCommand(t *testing.T) {
	tempEnv(t)
	old := buildFactory
	defer func() { buildFactory = old }()
	buildFactory = stubFactory()

	rec := writeRecipe(t)
	code, out, errs := run2(t, "build", "--recipe", rec, "--dist", filepath.Join(t.TempDir(), "dist"), "test.org/x")
	if code != 0 {
		t.Fatalf("build: code=%d err=%q", code, errs)
	}
	if !strings.Contains(out, "built test.org/x 1.0.0") || !strings.Contains(out, "bottle:") {
		t.Errorf("build output = %q", out)
	}
	// What it was built FROM, on the same screen as what came out: a digest
	// nobody ever sees is a digest nobody compares.
	if !strings.Contains(out, "source: https://x/v1.0.0.tgz (b0b0feed)") {
		t.Errorf("build output does not name the source: %q", out)
	}
}

func TestBuildCommandSetsRecipeDir(t *testing.T) {
	tempEnv(t)
	old := buildFactory
	defer func() { buildFactory = old }()

	var captured *build.Runner
	base := stubFactory()
	buildFactory = func(p string) *build.Runner { captured = base(p); return captured }

	rec := writeRecipe(t)
	code, _, errs := run2(t, "build", "--recipe", rec, "test.org/x")
	if code != 0 {
		t.Fatalf("build: code=%d err=%q", code, errs)
	}
	if captured == nil || captured.RecipeDir != filepath.Dir(rec) {
		t.Errorf("RecipeDir = %q, want %q", captured.RecipeDir, filepath.Dir(rec))
	}
}

func TestBuildCommandErrors(t *testing.T) {
	tempEnv(t)
	old := buildFactory
	defer func() { buildFactory = old }()
	rec := writeRecipe(t)

	// missing --recipe / no project
	if c, _, _ := run2(t, "build"); c != 2 {
		t.Errorf("no-recipe code=%d", c)
	}
	if c, _, _ := run2(t, "build", "--recipe", rec); c != 2 {
		t.Errorf("no-project code=%d", c)
	}
	// bad flag
	if c, _, _ := run2(t, "build", "-nope"); c != 2 {
		t.Errorf("bad-flag code=%d", c)
	}
	// unreadable recipe
	if c, _, _ := run2(t, "build", "--recipe", filepath.Join(t.TempDir(), "nope.yml"), "p"); c != 1 {
		t.Errorf("missing-recipe code=%d", c)
	}
	// invalid recipe content
	bad := filepath.Join(t.TempDir(), "bad.yml")
	os.WriteFile(bad, []byte("build: [oops\n"), 0o644)
	if c, _, _ := run2(t, "build", "--recipe", bad, "p"); c != 1 {
		t.Errorf("bad-recipe code=%d", c)
	}
	// invalid target (ZBK_TARGET) → Resolve error. Call runBuild directly:
	// run2 unsets ZBK_TARGET for isolation, which would hide this path.
	t.Setenv("ZBK_TARGET", "plan9/x86-64")
	var o, e bytes.Buffer
	if c := runBuild([]string{"--recipe", rec, "p"}, &o, &e); c != 1 {
		t.Errorf("bad-target code=%d", c)
	}
	t.Setenv("ZBK_TARGET", "")
	// Build error (factory whose PickVersion fails)
	buildFactory = func(string) *build.Runner {
		return &build.Runner{ResolveVersion: func(any, string) (string, string, error) { return "", "", os.ErrInvalid }}
	}
	if c, _, _ := run2(t, "build", "--recipe", rec, "p"); c != 1 {
		t.Errorf("build-error code=%d", c)
	}
}

func TestBuildResolvesZpkgxPath(t *testing.T) {
	tempEnv(t)
	oldF, oldL := buildFactory, lookPath
	defer func() { buildFactory, lookPath = oldF, oldL }()

	var gotBin string
	base := stubFactory()
	buildFactory = func(p string) *build.Runner { gotBin = p; return base(p) }
	rec := writeRecipe(t)

	// LookPath succeeds → the absolute path is handed to the factory.
	lookPath = func(name string) (string, error) { return "/abs/" + name, nil }
	if c, _, e := run2(t, "build", "--recipe", rec, "test.org/x"); c != 0 {
		t.Fatalf("build: code=%d err=%q", c, e)
	}
	if gotBin != "/abs/zpkgx" {
		t.Errorf("resolved zpkgx = %q, want /abs/zpkgx — the default is the binary we ship", gotBin)
	}

	// LookPath fails → the flag value is kept as given.
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if c, _, e := run2(t, "build", "--recipe", rec, "--zpkgx", "/explicit/zpkgx", "test.org/x"); c != 0 {
		t.Fatalf("build: code=%d err=%q", c, e)
	}
	if gotBin != "/explicit/zpkgx" {
		t.Errorf("unresolved zpkgx = %q, want /explicit/zpkgx", gotBin)
	}
}

// TestBuildVersionFlag proves --version <v> is passed to the resolver as an
// exact "=v" constraint, and its absence keeps the default "*".
func TestBuildVersionFlag(t *testing.T) {
	tempEnv(t)
	old := buildFactory
	defer func() { buildFactory = old }()

	var gotConstraint string
	buildFactory = func(string) *build.Runner {
		base := stubFactory()("")
		base.ResolveVersion = func(_ any, constraint string) (string, string, error) {
			gotConstraint = constraint
			// Return the version stubFactory's Run materialises, so the pipeline
			// completes; only the captured constraint is under test here.
			return "1.0.0", "v1.0.0", nil
		}
		return base
	}
	rec := writeRecipe(t)

	// --version set → "=1.9.4"
	if c, _, e := run2(t, "build", "--recipe", rec, "--version", "1.9.4", "test.org/x"); c != 0 {
		t.Fatalf("build --version: code=%d err=%q", c, e)
	}
	if gotConstraint != "=1.9.4" {
		t.Errorf("constraint = %q; want =1.9.4", gotConstraint)
	}

	// --version absent → "*"
	if c, _, e := run2(t, "build", "--recipe", rec, "test.org/x"); c != 0 {
		t.Fatalf("build no-version: code=%d err=%q", c, e)
	}
	if gotConstraint != "*" {
		t.Errorf("constraint = %q; want *", gotConstraint)
	}
}

func TestRunBash(t *testing.T) {
	// success: a trivial script runs to completion in the pure-Go interpreter.
	ok := filepath.Join(t.TempDir(), "ok.sh")
	os.WriteFile(ok, []byte("#!/bin/bash\nexport X=1\nif [ \"$X\" = 1 ]; then :; fi\nexit 0\n"), 0o755)
	if err := runBash(ok, []string{"PATH=/usr/bin:/bin"}); err != nil {
		t.Errorf("runBash ok: %v", err)
	}
	// non-zero exit → the interpreter returns an error.
	bad := filepath.Join(t.TempDir(), "bad.sh")
	os.WriteFile(bad, []byte("#!/bin/bash\nexit 3\n"), 0o755)
	if err := runBash(bad, nil); err == nil {
		t.Error("runBash should error on exit 3")
	}
	// open error: a path that does not exist.
	if err := runBash(filepath.Join(t.TempDir(), "nope.sh"), nil); err == nil {
		t.Error("runBash should error on a missing script")
	}
	// parse error: malformed shell syntax.
	mal := filepath.Join(t.TempDir(), "mal.sh")
	os.WriteFile(mal, []byte("if then fi\n"), 0o755)
	if err := runBash(mal, nil); err == nil {
		t.Error("runBash should error on a parse failure")
	}
	// interpreter-constructor error: forced via the seam.
	origNew := newInterp
	newInterp = func(...interp.RunnerOption) (*interp.Runner, error) { return nil, errBoom }
	defer func() { newInterp = origNew }()
	if err := runBash(ok, nil); err == nil {
		t.Error("runBash should propagate an interp.New error")
	}
}

func TestPickVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions.txt") {
			w.Write([]byte("1.0.0\n2.3.4\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	sd := bottle.DistBase
	bottle.DistBase = srv.URL
	defer func() { bottle.DistBase = sd }()

	v, err := pickVersion("acme.org/tool", "*")
	if err != nil || v != "2.3.4" {
		t.Errorf("pickVersion = %q %v", v, err)
	}
}

func TestRealBuildRunner(t *testing.T) {
	r := realBuildRunner("/opt/pkgx/bin/pkgx")
	if r.PickVersion == nil || r.ResolveVersion == nil || r.Fetch == nil || r.FetchGit == nil || r.Touch == nil ||
		r.Run == nil || r.FixUp == nil || r.WriteBottle == nil || r.ResolveDep == nil ||
		// Unwired, this field silently disables the whole closure question
		// and bootstrap goes back to asking the weaker one.
		r.ToolInstallable == nil || r.ZpkgxBin == "" || r.BashPath == "" {
		t.Errorf("realBuildRunner not fully wired: %+v", r)
	}
}

// toolInstallable asks whether the build can actually GET the tool, which is a
// different question from whether a version of it exists — and the difference
// is what stopped the s390x seed. libxcrypt build-depends on perl.org, perl.org
// was in the seed registry, and installing it needs libcrypt, which the soname
// map answers with libxcrypt: the project being built.
func TestToolInstallableAsksAboutTheClosure(t *testing.T) {
	var recipes map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions.txt") {
			// Every project this serves a recipe for has a bottle; anything
			// else does not, which is how a closure comes up short.
			for p := range recipes {
				if strings.Contains(r.URL.Path, "/"+p+"/") {
					w.Write([]byte("1.0.0\n"))
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		for p, body := range recipes {
			if strings.HasSuffix(r.URL.Path, "/"+p+"/package.yml") {
				fmt.Fprint(w, body)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	sd, so, sp := bottle.DistBase, bottle.PantryOverlay, bottle.PantryBase
	defer func() { bottle.DistBase, bottle.PantryOverlay, bottle.PantryBase = sd, so, sp }()
	bottle.DistBase, bottle.PantryOverlay, bottle.PantryBase = srv.URL, "", srv.URL

	// A tool whose closure is satisfiable.
	recipes = map[string]string{"acme.org": "dependencies:\n  zlib.net: '*'\n", "zlib.net": "{}\n"}
	if v, err := toolInstallable("acme.org", "*"); err != nil || v != "1.0.0" {
		t.Errorf("a satisfiable closure must resolve: %q %v", v, err)
	}

	// The same tool, with a dependency no bottle satisfies. A version check
	// alone still says yes — which is the bug this replaces.
	recipes = map[string]string{"acme.org": "dependencies:\n  absent.org: '*'\n"}
	if v, err := pickVersion("acme.org", "*"); err != nil || v != "1.0.0" {
		t.Fatalf("precondition: the version alone resolves: %q %v", v, err)
	}
	_, err := toolInstallable("acme.org", "*")
	if err == nil {
		t.Fatal("a tool whose closure cannot be installed is not a tool we have")
	}
	// The message must say WHICH of the two failed: "absent" and "here but
	// unusable" send a reader to different places.
	if !strings.Contains(err.Error(), "closure is not") || !strings.Contains(err.Error(), "acme.org") {
		t.Errorf("err = %v", err)
	}

	// And a tool with no bottle at all fails on the version, before any
	// closure walk — the message then names that, not a closure.
	recipes = map[string]string{}
	if _, err := toolInstallable("nowhere.org", "*"); err == nil {
		t.Error("want a version failure")
	} else if strings.Contains(err.Error(), "closure is not") {
		t.Errorf("an absent tool is not a closure failure: %v", err)
	}
}
