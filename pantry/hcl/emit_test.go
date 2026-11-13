package hcl

import (
	"strings"
	"testing"
)

// roundTrips is the only assertion that matters: Convert refuses anything that
// does not parse back into the same recipe, so a call that returns without an
// error has already been checked.
func roundTrips(t *testing.T, yml string) string {
	t.Helper()
	out, err := Convert([]byte(yml))
	if err != nil {
		t.Fatalf("Convert refused:\n%s\n--- from ---\n%s", err, yml)
	}
	return string(out)
}

// TestConvertDefusesTemplateSyntax is the trap the whole conversion turns on.
// HCL reads ${…} as an interpolation, and recipe scripts are full of shell
// expansions. Left alone it either fails to parse or evaluates part of a build
// script.
func TestConvertDefusesTemplateSyntax(t *testing.T) {
	got := roundTrips(t, "build:\n  script: |\n    make PREFIX=${DEST} %{weird}\n")
	if !strings.Contains(got, "$${DEST}") || !strings.Contains(got, "%%{weird}") {
		t.Errorf("both sigils must be doubled:\n%s", got)
	}
}

// A heredoc body is written VERBATIM at column 0. The first version indented
// it with <<-, which strips the COMMON leading whitespace — so a fixture whose
// own code is indented came back with that indentation gone. Twenty-eight
// recipes were refused for it, and the refusal is why none shipped altered.
func TestConvertKeepsIndentationInsideAScript(t *testing.T) {
	yml := "test:\n  fixture: |\n    #include <stdio.h>\n    int main(void) {\n        return 0;\n    }\n"
	got := roundTrips(t, yml)
	if !strings.Contains(got, "\n    return 0;\n") {
		t.Errorf("the fixture's own indentation must survive:\n%s", got)
	}
}

// A string with no trailing newline cannot be a heredoc: the terminator
// implies one. Those are quoted instead, rather than silently gaining a byte.
func TestConvertQuotesAStringWithNoFinalNewline(t *testing.T) {
	got := roundTrips(t, "build:\n  script: \"a\\nb\"\n")
	if strings.Contains(got, "<<EOT") {
		t.Errorf("no heredoc for a string that does not end in a newline:\n%s", got)
	}
}

// A heredoc inside a LIST: the terminator must be alone on its line, so the
// comma cannot follow it. `EOT,` is where fifteen recipes died with
// "Unterminated template string".
func TestConvertHeredocInsideAList(t *testing.T) {
	roundTrips(t, "build:\n  script:\n    - |\n      one\n      two\n    - echo done\n")
}

// A map whose keys are not identifiers cannot be a block — HCL has no
// attribute called "openssl.org" — so it is an object attribute with quoted
// keys. One whose keys ARE identifiers reads better as a block.
func TestConvertChoosesBlocksAndObjects(t *testing.T) {
	got := roundTrips(t, "dependencies:\n  openssl.org: ^1.1\nbuild:\n  script: make\n")
	if !strings.Contains(got, `"openssl.org" = "^1.1"`) {
		t.Errorf("a dotted key must be a quoted object key:\n%s", got)
	}
	if !strings.Contains(got, "build {") {
		t.Errorf("an identifier-keyed map reads as a block:\n%s", got)
	}
}

// What Convert REFUSES is the point, and what it refuses has narrowed.
//
// The whole-float case used to be here: MACOSX_DEPLOYMENT_TARGET: 11.0 comes
// back from HCL as an int, and four upstream recipes were refused for it —
// until the four were measured and found to generate byte-identical build
// scripts either way. A check stricter than the thing it protects is a check
// that refuses correct work.
//
// What is left is a defect in yaml.v3, not in either format: a string whose
// first line is indented marshals to a block scalar the same library cannot
// read back. artifact refuses rather than hand out YAML that fails later.
func TestConvertRefusesWhatCannotBeReadBack(t *testing.T) {
	_, err := Convert([]byte("test:\n  fixture: |4\n      indented\n  script: make\n"))
	if err == nil {
		t.Skip("yaml.v3 now round-trips this shape; the refusal is no longer exercised here")
	}
	if !strings.Contains(err.Error(), "read back") {
		t.Errorf("the refusal must say what failed: %v", err)
	}
}

// And the message, when recipes DO differ, names the path and the types — %#v
// renders int(11) and float64(11) identically, so the first version of this
// error was unusable.
func TestFirstDiffMessageNamesPathAndTypes(t *testing.T) {
	d := firstDiff(map[string]any{"k": "11"}, map[string]any{"k": int64(11)}, "")
	for _, want := range []string{"[k]", "string", "int64"} {
		if !strings.Contains(d, want) {
			t.Errorf("the message must name %q: %s", want, d)
		}
	}
}

func TestConvertRefusesBadInput(t *testing.T) {
	if _, err := Convert([]byte("provides: 123\n")); err == nil {
		t.Error("a recipe that fails the schema must not convert")
	}
	if _, err := Convert([]byte("\tnot: yaml\n")); err == nil {
		t.Error("undecodable yaml must not convert")
	}
}

// TestConvertEveryValueShape walks the shapes a recipe document can hold, in
// one recipe, so each arm of the renderer is exercised by something that also
// has to survive the round trip.
func TestConvertEveryValueShape(t *testing.T) {
	roundTrips(t, `
distributable:
  url: https://x/y.tar.gz
  strip-components: 1
dependencies:
  a.org: '*'
  b.org: 1
runtime:
  env:
    FLAG: true
    OFF: false
    EMPTY_LIST: []
    NUM: 3
    NESTED:
      deep.key: v
provides:
  - bin/x
build:
  script: make
platforms:
  - linux/x86-64
`)
}

// An empty map renders as {} rather than as a block with nothing in it, and an
// empty list as []. A block with an empty body parses, but it says "there is a
// build section" where the document says the section is empty.
func TestConvertEmptyContainers(t *testing.T) {
	got := roundTrips(t, "dependencies: {}\nprovides: []\nbuild:\n  script: make\n")
	if !strings.Contains(got, "dependencies = {}") || !strings.Contains(got, "provides = []") {
		t.Errorf("empty containers must stay empty and inline:\n%s", got)
	}
}

// A null survives as null: a recipe that says a key is deliberately empty is
// not the same as one that omits it.
func TestConvertNull(t *testing.T) {
	got := roundTrips(t, "dependencies:\n  a.org: ~\nbuild:\n  script: make\n")
	if !strings.Contains(got, "null") {
		t.Errorf("a null must render as null:\n%s", got)
	}
}

// firstDiff is what makes a refusal actionable. %#v renders int(1) and
// float64(1) identically, so the message has to carry the path and the types.
func TestFirstDiff(t *testing.T) {
	for _, c := range []struct {
		a, b any
		want string
	}{
		{map[string]any{"k": 1}, map[string]any{"k": "1"}, "[k]"},
		{map[string]any{"k": 1}, map[string]any{}, "present in the yaml"},
		{map[string]any{}, map[string]any{"k": 1}, "invented"},
		{[]any{1, 2}, []any{1}, "2 items from yaml, 1 from hcl"},
		{[]any{1, 2}, []any{1, 3}, "[1]"},
		{"a", "b", "."},
	} {
		got := firstDiff(c.a, c.b, "")
		if got == "" || !strings.Contains(got, c.want) {
			t.Errorf("firstDiff(%v,%v) = %q, want it to mention %q", c.a, c.b, got, c.want)
		}
	}
	// Equal things have no difference, and neither does a pair of nils.
	if d := firstDiff(map[string]any{"k": 1}, map[string]any{"k": 1}, ""); d != "" {
		t.Errorf("equal maps differ: %s", d)
	}
	if d := firstDiff(nil, nil, ""); d != "" {
		t.Errorf("two nils differ: %s", d)
	}
	if d := firstDiff(nil, 1, ""); d == "" {
		t.Error("nil against a value must differ")
	}
}

// firstDiff walks a *pantry.Recipe, so it has to handle a pointer and a
// struct — which is how Convert calls it.
func TestFirstDiffOnRecipes(t *testing.T) {
	a, err := Parse([]byte(`dependencies = { "a.org" = "^1" }`+"\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(`dependencies = { "a.org" = "^2" }`+"\n"), "x.hcl")
	if err != nil {
		t.Fatal(err)
	}
	d := firstDiff(a, b, "")
	if !strings.Contains(d, "Dependencies") || !strings.Contains(d, "a.org") {
		t.Errorf("want the struct field and the map key named, got %q", d)
	}
	if firstDiff(a, a, "") != "" {
		t.Error("a recipe must not differ from itself")
	}
	// A nil pointer on one side is a difference, not a panic.
	var nilRec *struct{ X int }
	if firstDiff(nilRec, &struct{ X int }{1}, "") == "" {
		t.Error("nil against a value must differ")
	}
}

// A float that is not whole keeps its point: 1.5 is not 1, and the %g arm is
// the only thing that says so.
func TestConvertFractionalNumber(t *testing.T) {
	got := roundTrips(t, "build:\n  env:\n    X: 1.5\n  script: make\n")
	if !strings.Contains(got, "1.5") {
		t.Errorf("a fractional number must survive:\n%s", got)
	}
}

// firstDiff walks exported fields only. An unexported one cannot be read
// through reflection without panicking, and skipping it is not a gap: nothing
// a recipe carries lives there.
func TestFirstDiffSkipsUnexportedFields(t *testing.T) {
	type withHidden struct {
		Shown  int
		hidden int
	}
	a := withHidden{Shown: 1, hidden: 2}
	b := withHidden{Shown: 1, hidden: 3}
	if d := firstDiff(a, b, ""); d != "" {
		t.Errorf("an unexported field must not be compared, got %q", d)
	}
	if d := firstDiff(withHidden{Shown: 1}, withHidden{Shown: 2}, ""); d == "" {
		t.Error("an exported one must be")
	}
}

// A script containing a line that reads exactly EOT would end the heredoc
// early, and everything after it would be parsed as HCL. The terminator is
// chosen to avoid the body.
func TestConvertScriptContainingTheTerminator(t *testing.T) {
	got := roundTrips(t, "build:\n  script: |\n    cat <<EOT > f\n    hello\n    EOT\n    make\n")
	if !strings.Contains(got, "<<EOT_") {
		t.Errorf("the terminator must step aside for the body:\n%s", got)
	}
}

// Two equal slices are equal — the arm that says so was the last uncovered
// line, and a differ that only ever found differences would be useless.
func TestFirstDiffEqualSlices(t *testing.T) {
	if d := firstDiff([]any{1, "a"}, []any{1, "a"}, ""); d != "" {
		t.Errorf("equal slices differ: %s", d)
	}
}

// Convert must never hand back text it could not read. The guard cannot be
// reached through the public API while Emit is correct — which is the point of
// having it — so the seam stands in for the defect it exists to catch. It has
// caught one already: a heredoc whose terminator appeared in the script.
func TestConvertRefusesUnparseableOutput(t *testing.T) {
	old := convertFn
	t.Cleanup(func() { convertFn = old })
	convertFn = func([]byte, string) ([]byte, error) { return []byte("build { script = \n"), nil }
	if _, err := Convert([]byte("build:\n  script: make\n")); err == nil ||
		!strings.Contains(err.Error(), "does not parse") {
		t.Errorf("want a refusal naming the parse failure, got %v", err)
	}
}

// TestConvertAcceptsANumberThatRendersTheSame.
//
// HCL has one number type, so a YAML float64(11) comes back as int64(11) and
// the structs differ. The BUILD does not: every numeric value reaches a script
// through transformScalar's fmt.Sprint, and both render "11". Measured, not
// argued — apache.org/thrift, isc.org/bind9, mpv.io and pwmt.org/zathura
// generate byte-identical build scripts from either recipe.
func TestConvertAcceptsANumberThatRendersTheSame(t *testing.T) {
	roundTrips(t, "build:\n  env:\n    MACOSX_DEPLOYMENT_TARGET: 11.0\n  script: make\n")
}

// And the tolerance stays narrow. A number whose TEXT differs is still a
// difference — float64(2.0250127e+07) is not int64(20250127), and that one
// turned out to be a client bug worth its own fix.
func TestFirstDiffNumberToleranceIsNarrow(t *testing.T) {
	if d := firstDiff(map[string]any{"k": 11.0}, map[string]any{"k": int64(11)}, ""); d != "" {
		t.Errorf("numbers rendering alike must be equal, got %q", d)
	}
	// And this is where the tolerance correctly declines to help:
	// fmt.Sprint(20250127.0) is "2.0250127e+07", which is NOT "20250127". The
	// two do not render alike, so they are not the same — and the real fix was
	// artifact keeping integral numbers as integers, not a looser comparison
	// here.
	if d := firstDiff(map[string]any{"k": 20250127.0}, map[string]any{"k": int64(20250127)}, ""); d == "" {
		t.Error("a float that renders in exponent form is not the integer")
	}
	if d := firstDiff(map[string]any{"k": 2.0250127e+07}, map[string]any{"k": "20250127"}, ""); d == "" {
		t.Error("a string is never a number, whatever it renders as")
	}
	if d := firstDiff(map[string]any{"k": 11.5}, map[string]any{"k": int64(11)}, ""); d == "" {
		t.Error("numbers rendering differently must still differ")
	}
}

// A list-form `versions:` carries TEXT. pantry.Parse re-reads each candidate's
// raw scalar from the YAML node so 5.0 keeps its ".0" — the distributable URL
// interpolates {{version.raw}}, and a candidate coerced to 5 fetches a tarball
// that does not exist. yaml.Unmarshal into a map has already lost that, so the
// emitter is handed the parsed recipe's list instead of the document's.
func TestConvertKeepsVersionText(t *testing.T) {
	got := roundTrips(t, "versions:\n  - 5.0\n  - 4.5\ndistributable:\n  url: https://x/{{version.raw}}.tar.gz\nbuild:\n  script: make\n")
	if !strings.Contains(got, `"5.0"`) {
		t.Errorf("a version's text must survive as text:\n%s", got)
	}
}

// Convert must refuse output that parses but says something else.
//
// No real recipe reaches this any more: the version-text and render-equal
// fixes removed the cases that did. It is the guard that would catch the NEXT
// emitter defect, so the seam stands in for one — the same seam that covers
// the parse-failure guard, and for the same reason.
func TestConvertRefusesADifferentRecipe(t *testing.T) {
	old := convertFn
	t.Cleanup(func() { convertFn = old })
	convertFn = func([]byte, string) ([]byte, error) {
		return []byte(`dependencies = { "openssl.org" = "^99" }` + "\n"), nil
	}

	_, err := Convert([]byte("dependencies:\n  openssl.org: ^3\nbuild:\n  script: make\n"))
	if err == nil {
		t.Fatal("want a refusal")
	}
	for _, want := range []string{"DIFFERENT recipe", "openssl.org", "^3", "^99"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q: %v", want, err)
		}
	}
}
