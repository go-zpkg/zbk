package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ⛔⛔ EVERY COMMAND THAT READS A RECIPE MUST READ BOTH FRONT-ENDS.
//
// `recipefile` exists so one place decides what a recipe is called and how it
// is read, and four commands still did it themselves with os.ReadFile +
// pantry.Parse — the YAML front-end, unconditionally. They could not read a
// `package.hcl` at all, while HCL is the default format: pantry-overlay holds
// 210 of them against 3 YAML (go-zpkg/bk#389).
//
// Every existing test of these commands used a YAML fixture, which is exactly
// why four commands lost HCL support without a lane going red. These are the
// fixtures that were missing.

// The HCL twin of versions_test.go's listRecipe. A list-form `versions` makes
// the candidates hardcoded, so no network is needed.
const listRecipeHCL = `versions      = ["1.2.0", "1.10.0", "1.3.0"]
distributable = "https://x/v{{version.raw}}.tgz"
build         = "true"
test          = "true"
`

func writeHCLRecipe(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The observed failure, before the fix:
//
//	$ bk versions -recipe .../llama.cpp/package.hcl
//	error: pantry: decode: yaml: unmarshal errors:
//	  line 14: cannot unmarshal !!str `display...` into pantry.Recipe
func TestVersionsReadsAnHCLRecipe(t *testing.T) {
	rec := writeHCLRecipe(t, "package.hcl", listRecipeHCL)
	code, out, errs := run2(t, "versions", "--recipe", rec)
	if code != 0 {
		t.Fatalf("versions on an HCL recipe: code=%d err=%q", code, errs)
	}
	// The SAME answer the YAML twin gives: newest first, version<TAB>tag.
	if want := "1.10.0\t1.10.0\n1.3.0\t1.3.0\n1.2.0\t1.2.0\n"; out != want {
		t.Errorf("versions output = %q; want %q", out, want)
	}
}

// A recipe whose EXTENSION is .hcl but whose body is YAML must fail as HCL
// rather than being silently retried: the extension is the declaration.
func TestTheExtensionDecidesTheFrontEnd(t *testing.T) {
	rec := writeHCLRecipe(t, "package.hcl", "versions:\n  - \"1.0.0\"\nbuild: \"true\"\n")
	if code, _, _ := run2(t, "versions", "--recipe", rec); code == 0 {
		t.Error("a YAML body named .hcl was accepted")
	}
}

// ⛔ `build` AND `test` MUST GET PAST PARSING. They cannot be run to
// completion here — that needs a toolchain and a network — so the assertion
// is on the FAILURE: whatever stops them, it must not be the YAML decoder
// choking on HCL, which is what used to stop them immediately.
func TestBuildAndTestNoLongerFailInTheYAMLDecoder(t *testing.T) {
	rec := writeHCLRecipe(t, "package.hcl", listRecipeHCL)
	for _, cmd := range []string{"build", "test"} {
		t.Run(cmd, func(t *testing.T) {
			args := []string{cmd, "--recipe", rec}
			if cmd == "test" {
				args = append(args, "acme.org") // `test` takes a project
			}
			_, out, errs := run2(t, args...)
			if s := out + errs; strings.Contains(s, "yaml:") {
				t.Errorf("%s still reads an HCL recipe as YAML: %s", cmd, s)
			}
		})
	}
}

// ⛔⛔ depgaps IS THE SERIOUS ONE, because it does not fail. It finds recipes
// with recipefile.IsRecipe — so it picks up `package.hcl` — then parsed them
// as YAML and took its "a recipe we cannot parse is a different problem" skip
// on every one. Over pantry-overlay that was 210 of 213 recipes examined by
// nobody, and a clean, confident, silent result for the rest.
//
// The fixture is the proof: an HCL recipe with an unsatisfiable dependency.
// Before the fix it was skipped and `unsatisfiable` returned nothing.
func TestDepgapsSeesAnHCLRecipe(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "hcl.example")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `distributable = { url = "https://x/v{{version}}.tgz" }
versions      = { github = "a/b/tags" }
build         = "make"
dependencies  = { "openssl.org" = "^1.1" }
`
	if err := os.WriteFile(filepath.Join(dir, "package.hcl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	have := map[string][]string{"openssl.org": {"3.5.0"}}
	got, _, err := unsatisfiable(root, linuxTarget(), have)
	if err != nil {
		t.Fatal(err)
	}
	blocking := got["openssl.org ^1.1"]
	if len(blocking) != 1 || blocking[0] != "hcl.example" {
		t.Fatalf("the HCL recipe was not examined: got %v", got)
	}
}

// AND A GENUINELY BROKEN RECIPE IS STILL SKIPPED. The fix must not turn the
// "cannot parse" skip into a failure, or one malformed file would stop the
// whole sweep — which is why that skip was written in the first place.
func TestDepgapsStillSkipsARecipeItCannotParse(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "broken.example")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.hcl"), []byte("this is = = not hcl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A readable neighbour, so a sweep that aborted would be visible as an
	// absence rather than as an empty tree.
	writeGapRecipe(t, root, "fine.example", minimal+"dependencies:\n  openssl.org: ^1.1\n")

	got, _, err := unsatisfiable(root, linuxTarget(), map[string][]string{"openssl.org": {"3.5.0"}})
	if err != nil {
		t.Fatalf("one unparseable recipe stopped the sweep: %v", err)
	}
	if blocking := got["openssl.org ^1.1"]; len(blocking) != 1 || blocking[0] != "fine.example" {
		t.Fatalf("the readable neighbour was not reported: %v", got)
	}
}

// ⛔⛔ THE WALK SAYS WHAT IT READ. A ranking is a claim about a population, and
// this walk once examined 3 recipes of 213 while printing a confident answer
// about the whole pantry. The parse bug is fixed; the silence that hid it for
// months is the other half, and a skip nobody counts will hide the next one.
func TestDepgapsCountsWhatItSkipped(t *testing.T) {
	root := t.TempDir()
	// One good YAML, one good HCL, one unparseable, one for another platform.
	writeGapRecipe(t, root, "ok.example", minimal+"dependencies:\n  openssl.org: ^1.1\n")
	hclDir := filepath.Join(root, "projects", "hcl.example")
	if err := os.MkdirAll(hclDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hclDir, "package.hcl"),
		[]byte("distributable = { url = \"https://x/v{{version}}.tgz\" }\nversions = { github = \"a/b/tags\" }\nbuild = \"make\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	brokenDir := filepath.Join(root, "projects", "broken.example")
	if err := os.MkdirAll(brokenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brokenDir, "package.hcl"), []byte("= = =\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeGapRecipe(t, root, "mac.example", minimal+"platforms:\n  - darwin\n")

	_, _, cen, err := unsatisfiableCounted(root, linuxTarget(), map[string][]string{"openssl.org": {"3.5.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if cen.examined != 2 {
		t.Errorf("examined = %d, want the two readable linux recipes", cen.examined)
	}
	if cen.unparsed != 1 {
		t.Errorf("unparsed = %d, want 1", cen.unparsed)
	}
	if cen.offPlatform != 1 {
		t.Errorf("offPlatform = %d, want 1", cen.offPlatform)
	}
	// And it must be legible, not just counted.
	if s := cen.String(); !strings.Contains(s, "2 recipe(s) examined") ||
		!strings.Contains(s, "1 did not parse") ||
		!strings.Contains(s, "1 not for this platform") {
		t.Errorf("the census does not read as a sentence: %q", s)
	}
}

// A census with nothing to report says only what it examined: a line of
// zeroes would train the reader to skip it.
func TestACleanCensusIsOneClause(t *testing.T) {
	if s := (census{examined: 7}).String(); s != "7 recipe(s) examined" {
		t.Errorf("clean census = %q", s)
	}
}
