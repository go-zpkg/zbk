package recipefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zbk/pantry"
)

// LoadWithDoc returns the recipe AND the keys the file states, from one read.
// Both front-ends, because the document is read by the front-end `parse` uses
// rather than by a second converter.
func TestLoadWithDocReadsEitherFrontEnd(t *testing.T) {
	p := t.TempDir()
	write(t, filepath.Join(p, "a.org"), "package.yml", yml)
	write(t, filepath.Join(p, "b.org"), "package.hcl", hclSrc)
	for _, proj := range []string{"a.org", "b.org"} {
		r, doc, err := LoadWithDoc(filepath.Join(p, proj))
		if err != nil {
			t.Fatalf("%s: %v", proj, err)
		}
		if r.Build == nil {
			t.Errorf("%s: the recipe did not decode", proj)
		}
		if _, ok := doc["build"]; !ok {
			t.Errorf("%s: the document does not state `build`: %v", proj, doc)
		}
		if _, ok := doc["distributable"]; ok {
			t.Errorf("%s: the document invented a key the file does not state", proj)
		}
	}
}

// ⛔⛔ A KEY THE FILE STATES AS null IS NOT A KEY THE FILE OMITS, and the typed
// Recipe cannot tell them apart: Distributable is `any`, so both are nil. The
// document can, which is the entire reason it is returned.
func TestLoadWithDocSeparatesAStatedNullFromAnOmittedKey(t *testing.T) {
	p := t.TempDir()
	write(t, filepath.Join(p, "stated"), "package.yml", "distributable: null\nbuild: make\n")
	write(t, filepath.Join(p, "omitted"), "package.yml", "build: make\n")

	sr, sdoc, err := LoadWithDoc(filepath.Join(p, "stated"))
	if err != nil {
		t.Fatal(err)
	}
	or, odoc, err := LoadWithDoc(filepath.Join(p, "omitted"))
	if err != nil {
		t.Fatal(err)
	}
	// The control: the typed field is identical in both, so a caller reading it
	// is answering a question it cannot see.
	if sr.Distributable != nil || or.Distributable != nil {
		t.Fatal("the premise of this test is that both decode to nil")
	}
	if _, ok := sdoc["distributable"]; !ok {
		t.Error("`distributable: null` is stated and the document must say so")
	}
	if _, ok := odoc["distributable"]; ok {
		t.Error("an omitted key must not appear in the document")
	}
}

// ⛔ A NON-STRING KEY DOES NOT SEPARATE THE TWO HALVES, and this is recorded
// because it was the reason an unreachable error arm looked reachable. The
// guess was that `1: x` would decode into the Recipe struct and satisfy a
// root-open schema while a map[string]any could not hold the key — so the
// document read would be the one to fail. `yaml.v3` coerces the key to "1"
// instead, and nothing fails at all. There is no input that parses as a recipe
// and not as a document, which is why the document now comes from the
// front-end rather than from a second read.
func TestANonStringKeyIsCoercedRatherThanRefused(t *testing.T) {
	p := t.TempDir()
	write(t, filepath.Join(p, "odd"), "package.yml", "build: make\n1: x\n")
	_, doc, err := LoadWithDoc(filepath.Join(p, "odd"))
	if err != nil {
		t.Fatalf("yaml.v3 coerces the key; nothing here should fail: %v", err)
	}
	if _, ok := doc["1"]; !ok {
		t.Errorf("the key was expected as the string \"1\": %v", doc)
	}
}

// A recipe the SCHEMA refuses comes back as that refusal, with the document
// withheld: a caller must not be handed keys from a file we have declined.
func TestLoadWithDocPassesASchemaRefusalThrough(t *testing.T) {
	p := t.TempDir()
	write(t, filepath.Join(p, "bad"), "package.yml", "provenance:\n  read: []\n")
	_, doc, err := LoadWithDoc(filepath.Join(p, "bad"))
	if !errors.Is(err, pantry.ErrSchema) {
		t.Fatalf("want a schema refusal, got %v", err)
	}
	if doc != nil {
		t.Errorf("a refused recipe must not come back with a document: %v", doc)
	}
}

// LoadWithDoc on a directory with no recipe is ErrNoRecipe, not a read error:
// the factory skips an absent recipe and records a malformed one.
func TestLoadWithDocOnADirectoryWithNoRecipe(t *testing.T) {
	if _, _, err := LoadWithDoc(t.TempDir()); !errors.Is(err, ErrNoRecipe) {
		t.Errorf("want ErrNoRecipe, got %v", err)
	}
}

// And on a path that is not there at all, the os error survives — a caller that
// spelled a filename wrong needs to see that, not "no recipe file".
func TestLoadWithDocOnAMissingPath(t *testing.T) {
	_, _, err := LoadWithDoc(filepath.Join(t.TempDir(), "nope", "package.yml"))
	if err == nil || errors.Is(err, ErrNoRecipe) {
		t.Errorf("want the os error, got %v", err)
	}
}

// A file whose front-end refuses it fails before the document is read, so the
// parse error is what the caller sees.
func TestLoadWithDocReportsAParseFailure(t *testing.T) {
	p := t.TempDir()
	write(t, filepath.Join(p, "bad"), "package.hcl", "build { script = \n")
	if _, _, err := LoadWithDoc(filepath.Join(p, "bad", "package.hcl")); err == nil {
		t.Fatal("a recipe that does not parse must not come back with a document")
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const yml = "dependencies:\n  openssl.org: ^1.1\nbuild: make\nprovides:\n  - bin/x\n"
const hclSrc = "dependencies = { \"openssl.org\" = \"^3\" }\nbuild { script = [\"make\"] }\nprovides = [\"bin/x\"]\n"

// TestLoadReadsEitherFrontEnd — and both end at the same schema, which is why
// pantry/hcl round-trips through YAML rather than decoding on its own.
func TestLoadReadsEitherFrontEnd(t *testing.T) {
	p := t.TempDir()
	write(t, Dir(p, "a.org"), "package.yml", yml)
	write(t, Dir(p, "b.org"), "package.hcl", hclSrc)

	a, err := Load(p, "a.org")
	if err != nil || a.Dependencies["openssl.org"] != "^1.1" {
		t.Errorf("yml: %+v, %v", a, err)
	}
	b, err := Load(p, "b.org")
	if err != nil || b.Dependencies["openssl.org"] != "^3" {
		t.Errorf("hcl: %+v, %v", b, err)
	}
}

// HCL wins when a project has both: that project is mid-conversion, and the
// converted file is the one its author is working on.
func TestLoadPrefersHCLDuringAConversion(t *testing.T) {
	p := t.TempDir()
	d := Dir(p, "both.org")
	write(t, d, "package.yml", yml)
	write(t, d, "package.hcl", hclSrc)
	r, err := Load(p, "both.org")
	if err != nil {
		t.Fatal(err)
	}
	if r.Dependencies["openssl.org"] != "^3" {
		t.Errorf("want the HCL recipe, got %v", r.Dependencies)
	}
}

// TestErrNoRecipeIsNotAParseError.
//
// The factory SKIPs a project with no recipe — a pantry need not be complete,
// and a closure walk names projects that resolve from upstream — while a
// recipe that exists and does not parse is a recorded failure. Collapsing both
// into "could not load" would make a broken recipe vanish from the failures
// list instead of appearing in it.
func TestErrNoRecipeIsNotAParseError(t *testing.T) {
	p := t.TempDir()
	if _, err := Load(p, "absent.org"); !errors.Is(err, ErrNoRecipe) {
		t.Errorf("absent must be ErrNoRecipe, got %v", err)
	}
	// The message names every filename tried: "no such file …/package.yml" on
	// a pantry that may hold either one reads as a missing project.
	_, err := Load(p, "absent.org")
	for _, want := range []string{"absent.org", "package.hcl", "package.yml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %q: %v", want, err)
		}
	}

	write(t, Dir(p, "broken.org"), "package.yml", "provides: 123\n")
	if _, e := Load(p, "broken.org"); e == nil || errors.Is(e, ErrNoRecipe) {
		t.Errorf("a malformed recipe must be an error and NOT ErrNoRecipe, got %v", e)
	}
}

// A tree walk asks about a NAME, not a project, and must accept both — this is
// what made depgaps blind to an HCL recipe while everything else built it.
func TestIsRecipe(t *testing.T) {
	for _, n := range Names {
		if !IsRecipe(n) {
			t.Errorf("IsRecipe(%q) = false", n)
		}
	}
	for _, n := range []string{"README.md", "package.yaml", "package.json", ""} {
		if IsRecipe(n) {
			t.Errorf("IsRecipe(%q) = true", n)
		}
	}
}

// LoadFile takes a path, as `bk build --recipe` does, and picks the front-end
// from the extension.
func TestLoadFile(t *testing.T) {
	p := t.TempDir()
	write(t, p, "package.hcl", hclSrc)
	write(t, p, "package.yml", yml)
	h, err := LoadFile(filepath.Join(p, "package.hcl"))
	if err != nil || h.Dependencies["openssl.org"] != "^3" {
		t.Errorf("hcl by path: %+v, %v", h, err)
	}
	y, err := LoadFile(filepath.Join(p, "package.yml"))
	if err != nil || y.Dependencies["openssl.org"] != "^1.1" {
		t.Errorf("yml by path: %+v, %v", y, err)
	}
	if _, err := LoadFile(filepath.Join(p, "gone.yml")); err == nil {
		t.Error("a missing path must fail")
	}
}

// ⛔⛔ ParseNamed IS FOR A CALLER THAT ALREADY HOLDS THE BYTES, and the NAME is
// what picks the front-end.
//
// `bk depgaps` walks a pantry, accepts any filename IsRecipe knows — so it
// finds `package.hcl` — and then read those bytes with the YAML front-end.
// Every HCL recipe became a parse error, which it skipped as malformed: 210 of
// pantry-overlay's 213 recipes examined by nobody, reported as a clean result
// (go-zpkg/bk#389).
func TestParseNamedPicksTheFrontEndByFilename(t *testing.T) {
	hclRec, err := ParseNamed([]byte(hclSrc), "package.hcl")
	if err != nil {
		t.Fatalf("an HCL recipe named package.hcl did not parse: %v", err)
	}
	if got := hclRec.Dependencies["openssl.org"]; got != "^3" {
		t.Errorf("openssl.org = %v, want ^3", got)
	}

	ymlRec, err := ParseNamed([]byte(yml), "package.yml")
	if err != nil {
		t.Fatalf("a YAML recipe named package.yml did not parse: %v", err)
	}
	if got := ymlRec.Dependencies["openssl.org"]; got != "^1.1" {
		t.Errorf("openssl.org = %v, want ^1.1", got)
	}

	// The name decides, so HCL bytes under a .yml name must FAIL rather than
	// be rescued by a retry: a retry would make the extension advisory, and
	// the two front-ends would stop being distinguishable in an error.
	if _, err := ParseNamed([]byte(hclSrc), "package.yml"); err == nil {
		t.Error("HCL content named package.yml was accepted")
	}
}

// ⛔⛔ A RECIPE PATH MAY BE THE DIRECTORY, so a caller need not choose the
// format to ask for the recipe.
//
// This package exists so one place decides what a recipe is called, and the
// spelling kept escaping it: four commands read `package.yml` directly
// (go-zpkg/bk#389), and the wasip1 workflow then spelled
// `/recipes/<slug>/package.yml` of its own, so converting that lane to HCL2
// could not be a reformat — it had to edit the workflow in the same commit or
// ship recipes the lane could not build.
func TestLoadFileTakesADirectoryAndLetsNamesDecide(t *testing.T) {
	p := t.TempDir()
	dir := Dir(p, "b.org")
	write(t, dir, "package.hcl", hclSrc)

	rec, err := LoadFile(dir)
	if err != nil {
		t.Fatalf("a recipe directory was not accepted: %v", err)
	}
	if got := rec.Dependencies["openssl.org"]; got != "^3" {
		t.Errorf("openssl.org = %v, want ^3 — the hcl front-end did not run", got)
	}
}

// And HCL wins over YAML by the same rule Load uses, so the two entry points
// cannot disagree about which file a project's recipe is.
func TestLoadFileOnADirectoryPrefersHCLLikeLoadDoes(t *testing.T) {
	p := t.TempDir()
	dir := Dir(p, "c.org")
	write(t, dir, "package.yml", yml)    // openssl.org ^1.1
	write(t, dir, "package.hcl", hclSrc) // openssl.org ^3

	viaFile, err := LoadFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	viaLoad, err := Load(p, "c.org")
	if err != nil {
		t.Fatal(err)
	}
	if viaFile.Dependencies["openssl.org"] != viaLoad.Dependencies["openssl.org"] {
		t.Errorf("LoadFile(dir) = %v but Load(project) = %v; the two entry points disagree",
			viaFile.Dependencies["openssl.org"], viaLoad.Dependencies["openssl.org"])
	}
	if got := viaFile.Dependencies["openssl.org"]; got != "^3" {
		t.Errorf("openssl.org = %v, want ^3 (the hcl)", got)
	}
}

// A directory holding no recipe is ErrNoRecipe — "this project has no recipe
// here" — and not a bare "is a directory" from the read, which is what the
// caller got before and could not act on.
func TestLoadFileOnADirectoryWithNoRecipeSaysSo(t *testing.T) {
	p := t.TempDir()
	dir := Dir(p, "d.org")
	write(t, dir, "README.md", "nothing here")

	_, err := LoadFile(dir)
	if !errors.Is(err, ErrNoRecipe) {
		t.Fatalf("err = %v, want ErrNoRecipe", err)
	}
	if !strings.Contains(err.Error(), "package.hcl") {
		t.Errorf("the error does not name what was tried: %v", err)
	}
}
