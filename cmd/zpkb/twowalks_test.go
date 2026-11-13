package main

import (
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

// TestTheTwoWalksAgree. bk has two closure walks and go-zpkg/bk#224 exists
// because teaching one of them something the other does not know makes
// `bk closure` describe a build the factory would not perform. That defect has
// been reproduced twice since — the logical overrides reached closureOf and
// not closureGraph, and the overlay merge landed in artifact and not in bk — and
// nothing compared the two.
//
// They read the overlay by DIFFERENT rules, deliberately:
//
//	closureOf      takes the UNION of both halves, as two separate recipes,
//	               because a dependency only the overlay declares still has to
//	               be BUILT (closureRecipes).
//	closureGraph   MERGES the overlay over the pantry, as a consumer resolves
//	               (recipefile.LoadMerged).
//
// Different rules can still owe the same answer, and for the RUNTIME closure
// they do — `dependencies` is a mapping, so merging it key by key reaches
// everything the union reaches. This pins that, over the shapes where the two
// rules could part.
func TestTheTwoWalksAgree(t *testing.T) {
	pan, ov := t.TempDir(), t.TempDir()

	// 1. The overlay adds an edge upstream does not have: perl.org NEEDs
	//    libcrypt.so.1 and upstream says nothing about it.
	writeClosureRecipe(t, pan, "perl.org", "dependencies:\n  gdbm.org: '*'\nbuild: make\n")
	writeClosureRecipe(t, ov, "perl.org", "dependencies:\n  crypt.org: '*'\nbuild: make\n")
	writeClosureRecipe(t, pan, "gdbm.org", "build: make\n")
	writeClosureRecipe(t, pan, "crypt.org", "build: make\n")

	// 2. Same dependency, different constraint in each half: surrealdb.com
	//    asks rust-lang.org for >=1.60 in the overlay and ~1.95 in the pantry.
	writeClosureRecipe(t, pan, "app.org", "dependencies:\n  lib.org: ~1.95\nbuild: make\n")
	writeClosureRecipe(t, ov, "app.org", "dependencies:\n  lib.org: '>=1.60'\nbuild: make\n")
	writeClosureRecipe(t, pan, "lib.org", "build: make\n")

	// 3. A REDUCED entry: the overlay states one key and nothing else, so
	//    reading it whole would lose upstream's dependencies entirely.
	writeClosureRecipe(t, pan, "curl.se", "dependencies:\n  zlib.net: ^1\n  ssl.org: ^3\nbuild: make\n")
	writeClosureRecipe(t, ov, "curl.se", "dependencies:\n  ssl.org: ^4\n")
	writeClosureRecipe(t, pan, "zlib.net", "build: make\n")
	writeClosureRecipe(t, pan, "ssl.org", "build: make\n")

	// 4. A project only the overlay carries, and 5. one only upstream has.
	writeClosureRecipe(t, ov, "ours.example", "dependencies:\n  lib.org: '*'\nbuild: make\n")
	writeClosureRecipe(t, pan, "theirs.example", "dependencies:\n  gdbm.org: '*'\nbuild: make\n")

	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	for _, root := range []string{"perl.org", "app.org", "curl.se", "ours.example", "theirs.example"} {
		t.Run(root, func(t *testing.T) {
			order, _, _ := closureOf(nil, ov, pan, tgt, []string{root}, func(string) {})
			g := newClosureGraph(nil, pan, tgt, false, nil)
			g.overlay = ov
			g.visit(root)

			a, b := append([]string(nil), order...), append([]string(nil), g.order...)
			sort.Strings(a)
			sort.Strings(b)
			if fmt.Sprint(a) != fmt.Sprint(b) {
				t.Errorf("the two walks disagree:\n  closureOf    %v\n  closureGraph %v", a, b)
			}
			// And the premise: each one reached something, so agreeing is not
			// two empty answers matching.
			if len(a) == 0 {
				t.Fatalf("premise: neither walk reached anything from %s", root)
			}
		})
	}

	// The shapes above are only worth comparing if they are actually there.
	order, _, _ := closureOf(nil, ov, pan, tgt, []string{"perl.org"}, func(string) {})
	if !slices.Contains(order, "crypt.org") || !slices.Contains(order, "gdbm.org") {
		t.Errorf("premise: perl.org must reach BOTH halves' edges, got %v", order)
	}
}
