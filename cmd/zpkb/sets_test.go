package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/logical"
)

// writeSetPantry lays out a pantry holding the named recipes, each given as
// raw package.yml text.
func writeSetPantry(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for proj, body := range files {
		p := filepath.Join(dir, "projects", proj)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "package.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const pkgRecipe = "distributable:\n  url: https://x/v{{version}}.tgz\nversions:\n  - 1.0.0\nbuild:\n  script: [make]\ntest:\n  script: [true]\n"

func TestASetExpandsToItsMembers(t *testing.T) {
	p := writeSetPantry(t, map[string]string{
		"acme.org/toolchain": "members:\n  \"acme.org/cc\": \"*\"\n  \"acme.org/ld\": \"~2.4\"\n",
		"acme.org/cc":        pkgRecipe,
		"acme.org/ld":        pkgRecipe,
	})
	var log []string
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/toolchain"}, func(s string) { log = append(log, s) })
	want := []string{"acme.org/cc", "acme.org/ld"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v; want %v", got, want)
	}
	// Sorted, not map order: Go randomises iteration, and roots arriving in a
	// different order every run give a different feedback arc set inside a
	// cycle — a build order that changes for no reason.
	for range 20 {
		if g := expandSets(&logical.Set{}, "", p, []string{"acme.org/toolchain"}, nil); strings.Join(g, " ") != strings.Join(want, " ") {
			t.Fatalf("expansion is not stable: %v", g)
		}
	}
	if !strings.Contains(strings.Join(log, "\n"), "names 2 member(s)") {
		t.Errorf("the expansion said nothing: %v", log)
	}
}

// A plain package is passed through untouched — the overwhelming majority of
// roots, and the case that must cost nothing.
func TestAPlainPackageIsNotTouched(t *testing.T) {
	p := writeSetPantry(t, map[string]string{"acme.org/cc": pkgRecipe})
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/cc"}, nil)
	if len(got) != 1 || got[0] != "acme.org/cc" {
		t.Errorf("got %v; want [acme.org/cc]", got)
	}
}

// An unreadable root stays a root: reporting it is the dependency walk's job,
// and swallowing it here would turn "this project does not exist" into
// "nothing to build".
func TestAnUnreadableRootSurvivesExpansion(t *testing.T) {
	p := writeSetPantry(t, map[string]string{"acme.org/cc": pkgRecipe})
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/nope"}, nil)
	if len(got) != 1 || got[0] != "acme.org/nope" {
		t.Errorf("got %v; want the root kept so the walk can report it", got)
	}
}

// A set may name another set, because otherwise the first person who wants
// "the toolchain plus three more" copies the toolchain's list.
func TestASetMayNameAnotherSet(t *testing.T) {
	p := writeSetPantry(t, map[string]string{
		"acme.org/base":  "members:\n  \"acme.org/cc\": \"*\"\n",
		"acme.org/extra": "members:\n  \"acme.org/base\": \"*\"\n  \"acme.org/zz\": \"*\"\n",
		"acme.org/cc":    pkgRecipe,
		"acme.org/zz":    pkgRecipe,
	})
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/extra"}, nil)
	if strings.Join(got, " ") != "acme.org/cc acme.org/zz" {
		t.Errorf("got %v; want the nested set flattened", got)
	}
}

// A cycle is REPORTED, not silently de-duplicated: a set that contains itself
// is a mistake someone should see, and quietly coping would hide the day two
// sets were written to include each other.
func TestASetThatContainsItselfIsReported(t *testing.T) {
	p := writeSetPantry(t, map[string]string{
		"acme.org/a":  "members:\n  \"acme.org/b\": \"*\"\n",
		"acme.org/b":  "members:\n  \"acme.org/a\": \"*\"\n  \"acme.org/cc\": \"*\"\n",
		"acme.org/cc": pkgRecipe,
	})
	var log []string
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/a"}, func(s string) { log = append(log, s) })
	joined := strings.Join(log, "\n")
	if !strings.Contains(joined, "contains itself") {
		t.Errorf("the cycle was not reported: %v", log)
	}
	// And the walk still yields what it could reach, rather than nothing.
	if strings.Join(got, " ") != "acme.org/cc" {
		t.Errorf("got %v; want the reachable member", got)
	}
}

// Both members AND a distributable is refused rather than guessed at.
func TestARecipeThatIsBothASetAndAPackageSaysSo(t *testing.T) {
	p := writeSetPantry(t, map[string]string{
		"acme.org/both": "members:\n  \"acme.org/cc\": \"*\"\n" + pkgRecipe,
		"acme.org/cc":   pkgRecipe,
	})
	var log []string
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/both"}, func(s string) { log = append(log, s) })
	joined := strings.Join(log, "\n")
	for _, want := range []string{"BOTH members and a distributable", "treating it as a package"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the conflict message lacks %q: %v", want, log)
		}
	}
	if strings.Join(got, " ") != "acme.org/both" {
		t.Errorf("got %v; want it kept as a package", got)
	}
}

// Two roots naming the same package yield it once: a closure with a duplicate
// root builds it twice.
func TestExpansionDeduplicates(t *testing.T) {
	p := writeSetPantry(t, map[string]string{
		"acme.org/s1": "members:\n  \"acme.org/cc\": \"*\"\n",
		"acme.org/s2": "members:\n  \"acme.org/cc\": \"*\"\n",
		"acme.org/cc": pkgRecipe,
	})
	got := expandSets(&logical.Set{}, "", p, []string{"acme.org/s1", "acme.org/s2"}, nil)
	if strings.Join(got, " ") != "acme.org/cc" {
		t.Errorf("got %v; want one entry", got)
	}
}
