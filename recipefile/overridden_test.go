package recipefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/logical"
)

func writeRecipe(t *testing.T, pantry, project, name, body string) {
	t.Helper()
	dir := filepath.Join(pantry, "projects", project)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setFrom(t *testing.T, body string) *logical.Set {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "o.hcl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := logical.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const minimalYAML = `distributable:
  url: https://acme.org/{{version}}.tar.gz
dependencies:
  openssl.org: ^1.1
build:
  script: make install
provides:
  - bin/acme
`

func TestLoadOverriddenAppliesAndLeavesTheFileAlone(t *testing.T) {
	pantry := t.TempDir()
	writeRecipe(t, pantry, "acme.org", "package.yml", "# a comment nobody may lose\n"+minimalYAML)
	set := setFrom(t, `
project = "acme.org"
why     = "our registry carries no openssl 1.x"
edits   = [{ path = "dependencies[\"openssl.org\"]", set = "^3" }]
`)
	r, err := LoadOverridden(set, pantry, "acme.org")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Dependencies["openssl.org"]; got != "^3" {
		t.Errorf("dependency = %v, want ^3", got)
	}
	// Nothing on disk moved — which is the whole reason for applying at load:
	// rewriting the document would drop the comment.
	b, err := os.ReadFile(filepath.Join(pantry, "projects", "acme.org", "package.yml"))
	if err != nil || !strings.HasPrefix(string(b), "# a comment nobody may lose") {
		t.Errorf("the file was rewritten: %q", string(b))
	}
}

// A project the set does not mention takes exactly the path it always took.
// Most of the pantry is in that position during the migration.
func TestLoadOverriddenLeavesAnUnmentionedProjectAlone(t *testing.T) {
	pantry := t.TempDir()
	writeRecipe(t, pantry, "acme.org", "package.yml", minimalYAML)
	set := setFrom(t, `
project = "other.org"
why     = "w"
edits   = [{ path = "a", set = 1 }]
`)
	r, err := LoadOverridden(set, pantry, "acme.org")
	if err != nil || r.Dependencies["openssl.org"] != "^1.1" {
		t.Fatalf("%v %v", r, err)
	}
	// And with no set at all.
	if _, err := LoadOverridden(nil, pantry, "acme.org"); err != nil {
		t.Fatal(err)
	}
}

// An HCL recipe goes through the same converter the client uses, so a recipe
// written either way is overridden identically.
func TestLoadOverriddenOnAnHCLRecipe(t *testing.T) {
	pantry := t.TempDir()
	writeRecipe(t, pantry, "acme.org", "package.hcl", `
distributable { url = "https://acme.org/{{version}}.tar.gz" }
dependencies = { "openssl.org" = "^1.1" }
build { script = "make install" }
provides = ["bin/acme"]
`)
	set := setFrom(t, `
project = "acme.org"
why     = "w"
edits   = [{ path = "dependencies[\"openssl.org\"]", set = "^3" }]
`)
	r, err := LoadOverridden(set, pantry, "acme.org")
	if err != nil {
		t.Fatal(err)
	}
	if r.Dependencies["openssl.org"] != "^3" {
		t.Errorf("got %v", r.Dependencies)
	}
}

func TestLoadOverriddenReportsFailures(t *testing.T) {
	pantry := t.TempDir()

	// No recipe at all.
	if _, err := LoadOverridden(nil, pantry, "absent.example"); err == nil {
		t.Error("a project with no recipe must be an error")
	}

	// An override whose premise is gone stops the load rather than quietly
	// building the unoverridden recipe — which is how a -Werror switch went
	// missing for weeks.
	writeRecipe(t, pantry, "acme.org", "package.yml", minimalYAML)
	gone := setFrom(t, `
project = "acme.org"
why     = "w"
edits   = [{ path = "build.script", from = "cmake", to = "cmake3" }]
`)
	if _, err := LoadOverridden(gone, pantry, "acme.org"); err == nil {
		t.Error("a premise that is gone must stop the load")
	}

	// An override that produces something a recipe may not say fails at the
	// schema, where every other recipe is checked.
	bad := setFrom(t, `
project = "acme.org"
why     = "w"
edits   = [{ path = "distributable", set = 7 }]
`)
	if _, err := LoadOverridden(bad, pantry, "acme.org"); err == nil {
		t.Error("an override that breaks the schema must fail")
	}

	// A recipe that is not the format its name claims.
	writeRecipe(t, pantry, "broken.example", "package.hcl", "distributable {")
	brokenSet := setFrom(t, `
project = "broken.example"
why     = "w"
edits   = [{ path = "a", set = 1 }]
`)
	if _, err := LoadOverridden(brokenSet, pantry, "broken.example"); err == nil {
		t.Error("a recipe that does not parse must fail")
	}

	// YAML that is not a mapping at all.
	writeRecipe(t, pantry, "list.example", "package.yml", "- one\n- two\n")
	listSet := setFrom(t, `
project = "list.example"
why     = "w"
edits   = [{ path = "a", set = 1 }]
`)
	if _, err := LoadOverridden(listSet, pantry, "list.example"); err == nil {
		t.Error("a recipe that is not a mapping must fail")
	}
}

// The seam: marshalling a document a parser produced cannot realistically
// fail, and swallowing the error would feed the schema an empty recipe.
func TestLoadOverriddenWhenTheDocumentCannotBeWrittenBack(t *testing.T) {
	pantry := t.TempDir()
	writeRecipe(t, pantry, "acme.org", "package.yml", minimalYAML)
	set := setFrom(t, `
project = "acme.org"
why     = "w"
edits   = [{ path = "dependencies[\"openssl.org\"]", set = "^3" }]
`)
	old := yamlMarshal
	t.Cleanup(func() { yamlMarshal = old })
	yamlMarshal = func(any) ([]byte, error) { return nil, os.ErrInvalid }
	if _, err := LoadOverridden(set, pantry, "acme.org"); err == nil {
		t.Error("want the marshal error, not an empty recipe")
	}
}

// The build recipe: the pantry with its override, falling back to the overlay
// only when the pantry has no such project.
//
// FALLBACK, not preference. For a project upstream carries, letting the
// overlay win would silently build something other than what the overrides
// say — the overlay is what a CONSUMER resolves, and the two halves fix
// different things.
func TestLoadBuildRecipe(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeRecipe(t, pantry, "both.org", "package.yml", minimalYAML)
	writeRecipe(t, overlay, "both.org", "package.hcl",
		"distributable { url = \"https://other.example/x.tar.gz\" }\nbuild { script = \"make\" }\nprovides = [\"bin/other\"]\n")
	writeRecipe(t, overlay, "ours.example", "package.hcl",
		"distributable { url = \"https://ours.example/x.tar.gz\" }\nbuild { script = \"make\" }\nprovides = [\"bin/ours\"]\n")
	set := setFrom(t, `
project = "both.org"
why     = "our registry carries no openssl 1.x"
edits   = [{ path = "dependencies[\"openssl.org\"]", set = "^3" }]
`)

	// The pantry wins, and the override is applied to it.
	r, dir, err := LoadBuildRecipe(set, overlay, pantry, "both.org")
	if err != nil {
		t.Fatal(err)
	}
	// The directory follows the recipe: the pantry's won, so it is the
	// pantry's directory, and the factory stages its fixtures from there.
	if dir != Dir(pantry, "both.org") {
		t.Errorf("dir = %q, want the pantry's", dir)
	}
	if r.Dependencies["openssl.org"] != "^3" {
		t.Errorf("the override did not reach the pantry recipe: %v", r.Dependencies)
	}
	if fmt.Sprint(r.Provides) != "[bin/acme]" {
		t.Errorf("the overlay won over the pantry: %v", r.Provides)
	}

	// Only in the overlay: that is the whole recipe, and it replaces a patch
	// that used to create the file.
	r, dir, err = LoadBuildRecipe(set, overlay, pantry, "ours.example")
	if err != nil {
		t.Fatal(err)
	}
	// And here the OVERLAY's. Computing it separately as Dir(pantry, …) is
	// what the factory did, and for the eight projects that live only in
	// the overlay it named a path that is not there.
	if dir != Dir(overlay, "ours.example") {
		t.Errorf("dir = %q, want the overlay's", dir)
	}
	if fmt.Sprint(r.Provides) != "[bin/ours]" {
		t.Errorf("got %v", r.Provides)
	}

	// In neither.
	if _, _, err := LoadBuildRecipe(set, overlay, pantry, "absent.example"); err == nil {
		t.Error("a project in neither half must be an error")
	}
	// With no overlay it is LoadOverridden exactly.
	if _, _, err := LoadBuildRecipe(set, "", pantry, "ours.example"); err == nil {
		t.Error("without an overlay there is nothing to fall back to")
	}
	// An error that is NOT "no recipe" propagates rather than falling back —
	// a pantry recipe that exists and does not parse must not be quietly
	// replaced by the overlay's.
	writeRecipe(t, pantry, "broken.example", "package.yml", "a: [\n")
	writeRecipe(t, overlay, "broken.example", "package.hcl", "build { script = \"make\" }\n")
	if _, _, err := LoadBuildRecipe(set, overlay, pantry, "broken.example"); err == nil {
		t.Error("a pantry recipe that does not parse must be reported, not replaced")
	}
}

// TestLoadMergedMerges pins the rule a REDUCED overlay depends on. An
// entry that states `dependencies` and nothing else is a fragment, and reading
// it whole gave a recipe with no build and no distributable — measured as
// `bk closure --build curl.se` collapsing from 54 projects to 8.
func TestLoadMergedMerges(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeRecipe(t, pantry, "acme.org", "package.yml", minimalYAML)
	writeRecipe(t, overlay, "acme.org", "package.hcl",
		"dependencies = { \"openssl.org\" = \"^3\" }\nprovides = [\"bin/only\"]\n")

	r, err := LoadMerged(nil, overlay, pantry, "acme.org")
	if err != nil {
		t.Fatal(err)
	}
	// Stated by the overlay: it wins.
	if r.Dependencies["openssl.org"] != "^3" {
		t.Errorf("the overlay did not win: %v", r.Dependencies)
	}
	// A list REPLACES rather than merging — there is no merge key for one.
	if fmt.Sprint(r.Provides) != "[bin/only]" {
		t.Errorf("a list must replace: %v", r.Provides)
	}
	// Omitted by the overlay: inherited. This is the whole point — the
	// fragment carries no build, and the walk still needs one.
	if !strings.Contains(fmt.Sprint(r.Build), "make install") {
		t.Errorf("upstream's build was not inherited: %v", r.Build)
	}
	if !strings.Contains(fmt.Sprint(r.Distributable), "acme.org") {
		t.Errorf("upstream's distributable was not inherited: %v", r.Distributable)
	}
}

func TestLoadMergedOneSidedAndAbsent(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeRecipe(t, pantry, "up.org", "package.yml", minimalYAML)
	writeRecipe(t, overlay, "ours.example", "package.hcl",
		"distributable { url = \"https://ours.example/x.tar.gz\" }\nbuild { script = \"make\" }\nprovides = [\"bin/ours\"]\n")

	// Upstream carries no such project: the overlay is the whole recipe.
	r, err := LoadMerged(nil, overlay, pantry, "ours.example")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.Provides) != "[bin/ours]" {
		t.Errorf("got %v", r.Provides)
	}
	// The overlay says nothing: upstream, untouched.
	if r, err = LoadMerged(nil, overlay, pantry, "up.org"); err != nil {
		t.Fatal(err)
	} else if fmt.Sprint(r.Provides) != "[bin/acme]" {
		t.Errorf("got %v", r.Provides)
	}
	// No overlay directory at all is the same question asked of the pantry.
	if _, err := LoadMerged(nil, "", pantry, "up.org"); err != nil {
		t.Fatal(err)
	}
	// In neither half.
	if _, err := LoadMerged(nil, overlay, pantry, "absent.example"); !errors.Is(err, ErrNoRecipe) {
		t.Errorf("want ErrNoRecipe, got %v", err)
	}
}

// TestLoadMergedRefusesWhatItCannotRead: a recipe that EXISTS and does
// not parse must never read as an absence. Skipping it silently would plan a
// build around a document nobody could read, on EITHER side.
func TestLoadMergedRefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, side, file, body string }{
		{"overlay HCL", "overlay", "package.hcl", "build { script = \n"},
		{"pantry YAML", "pantry", "package.yml", "a: [\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pantry, overlay := t.TempDir(), t.TempDir()
			writeRecipe(t, pantry, "x.org", "package.yml", minimalYAML)
			writeRecipe(t, overlay, "x.org", "package.hcl", "provides = [\"bin/x\"]\n")
			dir := overlay
			if tc.side == "pantry" {
				dir = pantry
			}
			writeRecipe(t, dir, "x.org", tc.file, tc.body)
			if _, err := LoadMerged(nil, overlay, pantry, "x.org"); err == nil {
				t.Fatal("a recipe that does not parse must be an error, not an absence")
			}
		})
	}
}

// TestLoadMergedWhenTheDocumentCannotBeWrittenBack reaches the marshal
// failure through the seam: the merged document is re-emitted as YAML for the
// pantry parser, and that write can fail.
func TestLoadMergedWhenTheDocumentCannotBeWrittenBack(t *testing.T) {
	pantry := t.TempDir()
	writeRecipe(t, pantry, "x.org", "package.yml", minimalYAML)
	old := yamlMarshal
	t.Cleanup(func() { yamlMarshal = old })
	yamlMarshal = func(any) ([]byte, error) { return nil, os.ErrInvalid }
	if _, err := LoadMerged(nil, "", pantry, "x.org"); err == nil {
		t.Fatal("want the marshal failure")
	}
}

// TestMergeRecipeReplacesAScalarWithAMap: the overlay states a table where
// upstream states something else. There is nothing to merge INTO, so the
// overlay's value replaces it whole.
func TestMergeRecipeReplacesAScalarWithAMap(t *testing.T) {
	got := mergeRecipe(
		map[string]any{"build": "make", "keep": 1},
		map[string]any{"build": map[string]any{"script": "make -j2"}},
	)
	b, ok := got["build"].(map[string]any)
	if !ok || b["script"] != "make -j2" {
		t.Errorf("got %#v", got["build"])
	}
	if got["keep"] != 1 {
		t.Errorf("an untouched key was lost: %#v", got)
	}
}

// TestLoadMergedAppliesTheOverridesToTheBase: the overlay carries 183 projects
// and the overrides describe 206. A walk that read the overlay's view for a
// project the overlay does NOT carry read it unoverridden — measured on a
// pristine pantry, `bk closure --build rsync.samba.org` listed gnu.org/libidn2
// without --overlay and not with it.
func TestLoadMergedAppliesTheOverridesToTheBase(t *testing.T) {
	pantry, overlay := t.TempDir(), t.TempDir()
	writeRecipe(t, pantry, "acme.org", "package.yml", minimalYAML)
	set := setFrom(t, `
project = "acme.org"
why     = "our registry carries no openssl 1.x"
edits   = [{ path = "dependencies[\"gnu.org/libidn2\"]", set = "*" }]
`)
	// The overlay says nothing about this project: the override still applies.
	r, err := LoadMerged(set, overlay, pantry, "acme.org")
	if err != nil {
		t.Fatal(err)
	}
	if r.Dependencies["gnu.org/libidn2"] != "*" {
		t.Errorf("the override did not reach the base: %v", r.Dependencies)
	}

	// And when the overlay DOES carry it, the overlay still wins for what it
	// states — it was generated from the overridden recipe.
	writeRecipe(t, overlay, "acme.org", "package.hcl",
		"dependencies = { \"gnu.org/libidn2\" = \"^2\" }\n")
	if r, err = LoadMerged(set, overlay, pantry, "acme.org"); err != nil {
		t.Fatal(err)
	} else if r.Dependencies["gnu.org/libidn2"] != "^2" {
		t.Errorf("the overlay did not win: %v", r.Dependencies)
	}

	// An override whose premise is gone is an error, not a silent skip.
	bad := setFrom(t, `
project = "acme.org"
why     = "premise"
edits   = [{ path = "dependencies[\"openssl.org\"]", set = "^3", expect = "^9" }]
`)
	if _, err := LoadMerged(bad, overlay, pantry, "acme.org"); err == nil {
		t.Error("an override that no longer holds must be reported")
	}
}
