package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lintTree writes a pantry checkout and returns its root.
func lintTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, "projects", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func lint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := runLint(args, &out, &errb)
	return rc, out.String(), errb.String()
}

// Both formats, through the loader the BUILDER uses. A pantry may hold either,
// and a check that knew only one reported "the layout changed" the day our
// overlay became HCL.
func TestLintReadsBothFormats(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"a.org/package.hcl":              "distributable { url = \"http://x/y.tgz\" }\n",
		"b.org/package.yml":              "distributable:\n  url: http://x/y.tgz\n",
		"x.org/protocol/xcb/package.hcl": "distributable { url = \"http://x/y.tgz\" }\n",
	})
	rc, out, errb := lint(t, "--dir", dir)
	if rc != 0 {
		t.Fatalf("rc = %d, stderr:\n%s", rc, errb)
	}
	// The COUNT is the part that matters: a sweep that read nothing reports
	// the same absence of problems as one that read everything.
	if !strings.Contains(out, "3 recipe(s) read") {
		t.Errorf("want the count of what was read: %q", out)
	}
}

// A recipe that does not parse is named, and the run fails.
func TestLintNamesWhatItCannotRead(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"good.org/package.hcl": "distributable { url = \"http://x/y.tgz\" }\n",
		"bad.org/package.hcl":  "build { script = \n",
	})
	rc, out, errb := lint(t, "--dir", dir)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(errb, "bad.org") || strings.Contains(errb, "good.org") {
		t.Errorf("the failure must name the recipe that failed, and only it:\n%s", errb)
	}
	if !strings.Contains(out, "2 recipe(s) read") {
		t.Errorf("both were read, and the count says so: %q", out)
	}
}

// An empty tree FAILS. A sweep that could not find its corpus reports the same
// "no problems" as one that read it all, and the count is the only thing that
// tells them apart — so the absence of a corpus has to be the loud case.
func TestLintRefusesAnEmptyTree(t *testing.T) {
	for name, dir := range map[string]string{
		"a projects/ with nothing in it": lintTree(t, nil),
		"no projects/ at all":            t.TempDir(),
	} {
		rc, _, errb := lint(t, "--dir", dir)
		if rc != 1 {
			t.Errorf("%s: rc = %d, want 1", name, rc)
		}
		if !strings.Contains(errb, "the layout changed") {
			t.Errorf("%s: the message must say what it means: %q", name, errb)
		}
	}
}

// A file that is not a recipe is not a recipe. The pantry holds READMEs and
// patches beside the recipes, and counting them would turn every one into a
// project with no recipe file.
func TestLintIgnoresWhatIsNotARecipe(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"a.org/package.hcl": "distributable { url = \"http://x/y.tgz\" }\n",
		"a.org/README.md":   "# notes\n",
		"a.org/fix.patch":   "--- a\n+++ b\n",
	})
	if rc, out, errb := lint(t, "--dir", dir); rc != 0 || !strings.Contains(out, "1 recipe(s) read") {
		t.Errorf("rc = %d, out = %q, stderr = %q", rc, out, errb)
	}
}

func TestLintBadFlag(t *testing.T) {
	if rc, _, _ := lint(t, "--nope"); rc != 2 {
		t.Errorf("an unknown flag must be a usage error, got %d", rc)
	}
}

// A tree the walk cannot descend is an error, not an empty corpus — the same
// distinction the empty-tree case makes, from the other direction.
func TestLintUnreadableTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read an unreadable directory")
	}
	dir := lintTree(t, map[string]string{"a.org/package.hcl": "x = 1\n"})
	sub := filepath.Join(dir, "projects", "a.org")
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	if rc, _, errb := lint(t, "--dir", dir); rc != 1 || !strings.Contains(errb, "lint:") {
		t.Errorf("rc = %d, stderr = %q", rc, errb)
	}
}

// A recipe sitting directly in projects/ belongs to no project. Counting it
// would name the pantry root as a project and then fail to load it.
func TestLintSkipsARecipeAtTheRoot(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"package.hcl":       "distributable { url = \"http://x/y.tgz\" }\n",
		"a.org/package.hcl": "distributable { url = \"http://x/y.tgz\" }\n",
	})
	rc, out, errb := lint(t, "--dir", dir)
	if rc != 0 || !strings.Contains(out, "1 recipe(s) read") {
		t.Errorf("rc = %d, out = %q, stderr = %q", rc, out, errb)
	}
}

// Through the top-level dispatch, which is the only thing a CI lane invokes.
func TestLintDispatch(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"a.org/package.hcl": "distributable { url = \"http://x/y.tgz\" }\n",
	})
	var out, errb bytes.Buffer
	if code := run([]string{"lint", "--dir", dir}, &out, &errb); code != 0 {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "1 recipe(s) read") {
		t.Errorf("want the count on stdout, got %q", out.String())
	}
}

// ⛔⛔ A FIELD NOTHING DECODES IS A FIELD NOTHING CAN REQUIRE. Before
// `provenance` was typed and enumerated, a recipe could carry it and zbk
// would accept it and drop it — `additionalProperties` is true at the root —
// which reads, to anyone opening the recipe, as a record that exists.
func TestLintReadsProvenance(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"acme.org/package.yml": "distributable:\n  url: https://acme.org/x.tar.gz\n" +
			"provenance:\n  read:\n    - configure\n    - README\n" +
			"  note: ./configure then make install, as the README documents\n",
	})
	rc, out, errb := lint(t, "--dir", dir, "--require-provenance")
	if rc != 0 {
		t.Fatalf("a recipe that records its provenance must pass: rc=%d\n%s", rc, errb)
	}
	if !strings.Contains(out, "1 recipe(s) read") {
		t.Errorf("the denominator is missing:\n%s", out)
	}
}

// ⛔ The requirement is about OUR recipes, so it is a FLAG and not the
// schema: making it a schema rule would refuse every foreign recipe we still
// read, which is the mistake closing `additionalProperties` made when the
// bootstrap toolchain's own recipes became unreadable (go-zpkg/zbk#427).
func TestLintRequiresProvenanceOnlyWhenAsked(t *testing.T) {
	files := map[string]string{
		"acme.org/package.yml": "distributable:\n  url: https://acme.org/x.tar.gz\n",
	}
	if rc, _, errb := lint(t, "--dir", lintTree(t, files)); rc != 0 {
		t.Fatalf("without the flag a recipe needs no provenance: rc=%d\n%s", rc, errb)
	}
	rc, _, errb := lint(t, "--dir", lintTree(t, files), "--require-provenance")
	if rc != 1 {
		t.Fatalf("with the flag it must fail: rc=%d", rc)
	}
	for _, want := range []string{"1 of 1 recipe(s) record no provenance", "acme.org"} {
		if !strings.Contains(errb, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, errb)
		}
	}
}

// A recipe that packages nothing of its own — a set, or a project whose files
// come from its dependencies — has no build to have derived from anything.
func TestLintExemptsARecipeWithNoDistributable(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"acme.org/set/package.yml": "members:\n  acme.org/tool: '*'\n",
	})
	if rc, _, errb := lint(t, "--dir", dir, "--require-provenance"); rc != 0 {
		t.Errorf("a recipe with no distributable packages nothing: rc=%d\n%s", rc, errb)
	}
}

// ⛔ AND A PROVENANCE BLOCK WITH NOTHING READ SAYS LESS THAN NONE: it looks
// like a record and names no file. The schema refuses it, so this cannot be
// satisfied by an empty gesture.
func TestLintRefusesAnEmptyProvenance(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"acme.org/package.yml": "distributable:\n  url: https://acme.org/x.tar.gz\n" +
			"provenance:\n  read: []\n",
	})
	rc, _, errb := lint(t, "--dir", dir, "--require-provenance")
	if rc != 1 || !strings.Contains(errb, "cannot be read") {
		t.Errorf("an empty `read` must be refused by the schema: rc=%d\n%s", rc, errb)
	}
}

// ⛔ `consulted` IS A CITATION LIST AND MUST SURVIVE THE ROUND TRIP. Reading
// how Nix, Guix, Spack, Homebrew, Debian or Fedora package the same project
// is bibliography — their packaging is where the facts live, and a fact has
// no author. What we do not take is their expression, which is why `read`
// (what the build derives from) and `consulted` (what was learned from) are
// separate fields rather than one list.
func TestLintReadsWhatWasConsulted(t *testing.T) {
	dir := lintTree(t, map[string]string{
		"acme.org/package.yml": "distributable:\n  url: https://acme.org/x.tar.gz\n" +
			"provenance:\n  read:\n    - configure\n" +
			"  consulted:\n    - nixpkgs pkgs/development/libraries/acme\n" +
			"    - guix gnu/packages/acme.scm\n    - spack var/spack/repos/builtin/packages/acme\n" +
			"  note: ./configure --static, and the darwin flag is the one every other distro sets\n",
	})
	rc, _, errb := lint(t, "--dir", dir, "--require-provenance")
	if rc != 0 {
		t.Fatalf("a recipe citing its bibliography must pass: rc=%d\n%s", rc, errb)
	}
}
