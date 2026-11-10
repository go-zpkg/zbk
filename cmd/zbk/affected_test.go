package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pantryOf writes a pantry of recipes: project -> HCL body.
func pantryOf(t *testing.T, recipes map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for proj, body := range recipes {
		dir := filepath.Join(root, "projects", filepath.FromSlash(proj))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.hcl"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// dep is the smallest recipe that declares runtime dependencies.
func dep(on ...string) string {
	var b strings.Builder
	b.WriteString("distributable { url = \"https://x/{{version}}.tar.gz\" }\nprovides = [\"bin/x\"]\n")
	// ⛔ `dependencies = { … }`, with the `=`. It is a MAP attribute, not a
	// block, and the first version of this fixture wrote it as a block: every
	// recipe with a dependency then failed to PARSE, the walk recorded it as a
	// project with no recipe, and the gate below refused for the right reason
	// about the wrong thing. A fixture that does not parse tests the error path.
	if len(on) > 0 {
		b.WriteString("dependencies = {\n")
		for _, o := range on {
			b.WriteString("  \"" + o + "\" = \"*\"\n")
		}
		b.WriteString("}\n")
	}
	return b.String()
}

// TestItWalksTheWholePantryNotTheNamedProjects is the property a naive
// implementation gets wrong, silently and in the dangerous direction.
//
// ⛔⛔ The reverse closure of X is only complete if the graph holds EVERY
// project that could depend on X. Seeding the walk with X reaches what X needs
// and learns nothing about who needs X — and the answer, "nothing to rebuild",
// is indistinguishable from a correct one.
//
// Here `top` depends on `mid` depends on `leaf`, and NOTHING depends on `top`.
// A walk seeded at `leaf` would report only `leaf`.
func TestItWalksTheWholePantryNotTheNamedProjects(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/leaf": dep(),
		"a.org/mid":  dep("a.org/leaf"),
		"a.org/top":  dep("a.org/mid"),
	})
	var out, errb bytes.Buffer
	if code := runAffected([]string{"-pantry", p, "a.org/leaf"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d\n%s%s", code, out.String(), errb.String())
	}
	for _, want := range []string{"a.org/leaf", "a.org/mid", "a.org/top"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("%s is missing from the rebuild set:\n%s", want, out.String())
		}
	}
	if !strings.Contains(out.String(), "3 project(s) to rebuild") {
		t.Errorf("the count is wrong:\n%s", out.String())
	}
}

// TestTheNamedProjectIsInTheSet, because a plan that rebuilds only the
// dependents rebuilds them against the unfixed thing.
func TestTheNamedProjectIsInTheSet(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/leaf": dep(),
		"a.org/mid":  dep("a.org/leaf"),
	})
	var out, errb bytes.Buffer
	runAffected([]string{"-pantry", p, "a.org/leaf"}, &out, &errb)
	if !strings.Contains(out.String(), "* a.org/leaf") {
		t.Errorf("the named project is not marked in the set:\n%s", out.String())
	}
}

// TestDependenciesComeFirst: the list is a plan, so it has to be executable in
// the order it is printed.
func TestDependenciesComeFirst(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/leaf": dep(),
		"a.org/mid":  dep("a.org/leaf"),
		"a.org/top":  dep("a.org/mid"),
	})
	var out, errb bytes.Buffer
	runAffected([]string{"-pantry", p, "a.org/leaf"}, &out, &errb)
	s := out.String()
	leaf, mid, top := strings.Index(s, "a.org/leaf"), strings.Index(s, "a.org/mid"), strings.Index(s, "a.org/top")
	if !(leaf < mid && mid < top) {
		t.Errorf("not in dependency order (leaf=%d mid=%d top=%d):\n%s", leaf, mid, top, s)
	}
}

// TestSomethingThatDependsOnNothingAffectedIsNotInTheSet — the set has to be
// the answer, not the pantry.
func TestSomethingThatDependsOnNothingAffectedIsNotInTheSet(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/leaf":      dep(),
		"a.org/mid":       dep("a.org/leaf"),
		"b.org/unrelated": dep(),
	})
	var out, errb bytes.Buffer
	runAffected([]string{"-pantry", p, "a.org/leaf"}, &out, &errb)
	if strings.Contains(out.String(), "b.org/unrelated") {
		t.Errorf("an unrelated project is in the rebuild set:\n%s", out.String())
	}
}

// TestAGraphWithHolesIsRefused is the gate.
//
// ⛔⛔ A project named as a dependency whose recipe is absent cannot be read,
// so we cannot know whether IT depends on an affected project — which would
// make it affected, and its dependents affected too. The set is then a LOWER
// BOUND, and a lower bound presented as an answer is how a rebuild misses the
// package that mattered.
func TestAGraphWithHolesIsRefused(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/leaf": dep(),
		"a.org/mid":  dep("a.org/leaf", "nowhere.org/ghost"),
	})
	var out, errb bytes.Buffer
	code := runAffected([]string{"-pantry", p, "a.org/leaf"}, &out, &errb)
	if code != 2 {
		t.Fatalf("code=%d, want 2 — a holed graph must not answer\n%s%s", code, out.String(), errb.String())
	}
	for _, want := range []string{"nowhere.org/ghost", "lower bound"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("the refusal does not say %q:\n%s", want, errb.String())
		}
	}
}

// TestTheDerogationStampsTheHoles: --allow-missing answers, and PRINTS what it
// could not read, because an exemption nobody can see is how the next person
// trusts the number.
func TestTheDerogationStampsTheHoles(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/leaf": dep(),
		"a.org/mid":  dep("a.org/leaf", "nowhere.org/ghost"),
	})
	var out, errb bytes.Buffer
	code := runAffected([]string{"-pantry", p, "--allow-missing", "a.org/leaf"}, &out, &errb)
	if code != 0 {
		t.Fatalf("code=%d with --allow-missing\n%s%s", code, out.String(), errb.String())
	}
	for _, want := range []string{"LOWER BOUND", "nowhere.org/ghost"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the exemption left no trace (%q missing):\n%s", want, out.String())
		}
	}
}

// TestAnEmptyPantryIsRefused. ⛔ The reverse closure over an empty graph is
// "nothing needs rebuilding" — the most dangerous answer this can give, and
// the one a wrong --pantry produces.
func TestAnEmptyPantryIsRefused(t *testing.T) {
	var out, errb bytes.Buffer
	code := runAffected([]string{"-pantry", t.TempDir(), "a.org/leaf"}, &out, &errb)
	if code != 2 {
		t.Fatalf("code=%d over an empty pantry, want 2\n%s", code, out.String())
	}
	if !strings.Contains(errb.String(), "nothing needs rebuilding") {
		t.Errorf("the refusal does not name the danger:\n%s", errb.String())
	}
}

// TestANamedProjectThatIsNotHereIsRefused: a project nobody can find is not a
// project with no dependents.
func TestANamedProjectThatIsNotHereIsRefused(t *testing.T) {
	p := pantryOf(t, map[string]string{"a.org/leaf": dep()})
	var out, errb bytes.Buffer
	code := runAffected([]string{"-pantry", p, "a.org/typo"}, &out, &errb)
	if code != 2 {
		t.Fatalf("code=%d for an unknown project, want 2\n%s", code, out.String())
	}
	if !strings.Contains(errb.String(), "a.org/typo") {
		t.Errorf("the refusal does not name it:\n%s", errb.String())
	}
}

// TestNamingNothingIsRefused.
func TestNamingNothingIsRefused(t *testing.T) {
	p := pantryOf(t, map[string]string{"a.org/leaf": dep()})
	var out, errb bytes.Buffer
	if code := runAffected([]string{"-pantry", p}, &out, &errb); code != 2 {
		t.Errorf("code=%d with no project named, want 2", code)
	}
}

// TestBuildDependenciesAreOptionalAndCounted: a project that only BUILDS
// against an affected one still has to be rebuilt when the fix changes a
// header or a static library — but that is a different question from the
// runtime one, so it is a flag.
func TestBuildDependenciesAreOptionalAndCounted(t *testing.T) {
	buildDep := "distributable { url = \"https://x/{{version}}.tar.gz\" }\n" +
		"provides = [\"bin/x\"]\n" +
		"build {\n  dependencies = { \"a.org/leaf\" = \"*\" }\n  script = \"make\"\n}\n"
	p := pantryOf(t, map[string]string{
		"a.org/leaf":     dep(),
		"a.org/buildsOn": buildDep,
	})

	var out, errb bytes.Buffer
	runAffected([]string{"-pantry", p, "a.org/leaf"}, &out, &errb)
	if strings.Contains(out.String(), "a.org/buildsOn") {
		t.Errorf("a BUILD-only dependent appeared in the runtime set:\n%s", out.String())
	}

	out.Reset()
	errb.Reset()
	runAffected([]string{"-pantry", p, "-build", "a.org/leaf"}, &out, &errb)
	if !strings.Contains(out.String(), "a.org/buildsOn") {
		t.Errorf("--build did not reach the build-only dependent:\n%s%s", out.String(), errb.String())
	}
}

// TestACycleTerminates. The build graph has cycles by construction — gcc
// build-depends on gcc — and a reverse walk that did not mark before
// recursing would not return.
func TestACycleTerminates(t *testing.T) {
	p := pantryOf(t, map[string]string{
		"a.org/one": dep("a.org/two"),
		"a.org/two": dep("a.org/one"),
	})
	var out, errb bytes.Buffer
	if code := runAffected([]string{"-pantry", p, "a.org/one"}, &out, &errb); code != 0 {
		t.Fatalf("code=%d on a cycle\n%s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "2 project(s) to rebuild") {
		t.Errorf("a cycle should put both in the set:\n%s", out.String())
	}
}

// TestTheDispatchReachesIt.
func TestAffectedIsReachableFromTheDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"affected"}, &out, &errb); code != 2 {
		t.Errorf("code=%d, want 2 — no project was named", code)
	}
	if !strings.Contains(errb.String(), "affected:") {
		t.Errorf("`zbk affected` did not reach runAffected: %s", errb.String())
	}
}
