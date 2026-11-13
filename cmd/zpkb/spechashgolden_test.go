package main

import (
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// ⛔⛔ THE LOCK HASH IS A PUBLISHED VALUE AND THIS PINS IT.
//
// Every lock file ever written holds hashes computed by specHash, and
// `zpkb lock --check` compares them. A refactor that moves one byte of the
// canonical form silently invalidates all of them — `--check` would report
// every project as changed, which reads as "the pantry moved" rather than
// "the tool did".
//
// There was no such test when the canonical form was lifted out of
// `package main` into zpkb/spec. The suite passed, and it proved nothing: not
// one test named a hash VALUE, so the whole lock suite would have passed on
// a different format. The equivalence was real —
//
//	Fprintf("dep %s %s\n", d, dh)  ==  Fprintf("dep %s\n", d+" "+dh)
//
// — but it was established by reading, and reading is not a control.
func TestTheLockSpecHashIsTheValueLockFilesHold(t *testing.T) {
	rec := &pantry.Recipe{Versions: map[string]any{"github": "a/b/tags"}}
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}

	got, err := specHash(
		[]*pantry.Recipe{rec}, "acme.org/tool", "1.2.3", tgt,
		map[string]string{"dep.org/lib": "sha256:beef"},
		[]string{"dep.org/lib", "absent.org/x"},
	)
	if err != nil {
		t.Fatal(err)
	}
	// ⛔ A LITERAL, AND IT WAS TAKEN FROM THE CODE AS IT STOOD BEFORE THE
	// MOVE, not after. The pre-refactor implementation was restored from git
	// and run against this same input; both produce this value, which is what
	// makes the extraction provably byte-for-byte rather than argued to be.
	//
	// If this changes, the format changed: either restore it, or accept that
	// every existing lock is invalidated and say so where people will read it.
	const want = "sha256:e47e158cd9d5d25a0fac14c4deaf4877af16d17c8780a14f02f9a6f0e8839894"
	if got != want {
		t.Errorf("the lock spec hash moved:\n got %s\nwant %s\n\n"+
			"Every lock file in existence holds hashes in the OLD form, and "+
			"`lock --check` compares against them.", got, want)
	}
}

// And a dependency with NO recipe hashes differently from one that is absent
// — the distinction the "(no recipe)" placeholder exists for.
func TestADependencyWithNoRecipeIsNotTheSameAsNoDependency(t *testing.T) {
	rec := &pantry.Recipe{Versions: map[string]any{"github": "a/b/tags"}}
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}

	withUnknown, err := specHash([]*pantry.Recipe{rec}, "p", "1", tgt, nil, []string{"dep.org/lib"})
	if err != nil {
		t.Fatal(err)
	}
	withNone, err := specHash([]*pantry.Recipe{rec}, "p", "1", tgt, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if withUnknown == withNone {
		t.Error("a dependency we have no recipe for hashes the same as having no dependency")
	}
}
