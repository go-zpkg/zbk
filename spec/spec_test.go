package spec

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

var tgt = target.Target{Platform: "linux", Arch: "x86-64"}

func rec(v string) *pantry.Recipe {
	return &pantry.Recipe{Versions: map[string]any{"github": v}}
}

// ⛔⛔ THE WHOLE POINT: A RECIPE THAT CHANGED MUST MOVE THE HASH. Pinning
// versions catches an upstream that moved; hashing the recipe catches the
// other half — a build script edited in the pantry resolves to the same
// version and produces a different package. Versions alone call those two
// builds the same.
func TestEditingTheRecipeMovesTheHash(t *testing.T) {
	a, err := Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.0", tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash(DomainBuild, []*pantry.Recipe{rec("other/b/tags")}, "p", "1.0", tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two different recipes hash alike — the recipe is not in the hash")
	}
}

// ⛔ EVERY FIELD IS IN IT, and a test that only checked the recipe would miss
// the one that matters most in practice: the platform. A darwin build and a
// linux build of one version are different artifacts.
func TestEveryFieldMovesTheHash(t *testing.T) {
	base, err := Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.0", tgt, []string{"d 1"})
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func() (string, error){
		"platform": func() (string, error) {
			return Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.0",
				target.Target{Platform: "darwin", Arch: "x86-64"}, []string{"d 1"})
		},
		"arch": func() (string, error) {
			return Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.0",
				target.Target{Platform: "linux", Arch: "aarch64"}, []string{"d 1"})
		},
		"project": func() (string, error) {
			return Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "q", "1.0", tgt, []string{"d 1"})
		},
		"version": func() (string, error) {
			return Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.1", tgt, []string{"d 1"})
		},
		"dependency": func() (string, error) {
			return Hash(DomainBuild, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.0", tgt, []string{"d 2"})
		},
		"domain": func() (string, error) {
			return Hash(DomainLock, []*pantry.Recipe{rec("a/b/tags")}, "p", "1.0", tgt, []string{"d 1"})
		},
	} {
		got, err := f()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == base {
			t.Errorf("changing the %s did not move the hash", name)
		}
	}
}

// ⛔⛔ TWO QUESTIONS MUST NOT SHARE A DOMAIN. `lock` identifies a dependency
// by its own spec hash; a BUILD identifies one by its resolved store prefix.
// Under one domain a value computed for either could be compared against the
// other, and the comparison would be meaningless rather than obviously wrong.
func TestTheTwoDomainsAreDifferentStrings(t *testing.T) {
	if DomainLock == DomainBuild {
		t.Fatal("the two domains are the same string")
	}
	// ⛔ AND DomainLock IS FROZEN. Every lock file ever written holds hashes
	// computed under it, and `lock --check` compares them.
	if DomainLock != "bk-lock-spec-hash v1" {
		t.Errorf("DomainLock = %q — changing it invalidates every lock in existence", DomainLock)
	}
}

// BOTH HALVES OF A RECIPE, in the order the closure reads them. A project can
// be described by the pantry AND by our overlay, and a hash over one half
// describes a different graph from the one beside it.
func TestBothRecipeHalvesAreHashedAndOrderMatters(t *testing.T) {
	one, err := Hash(DomainBuild, []*pantry.Recipe{rec("a")}, "p", "1.0", tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Hash(DomainBuild, []*pantry.Recipe{rec("a"), rec("b")}, "p", "1.0", tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Error("a second recipe half did not move the hash")
	}
	swapped, err := Hash(DomainBuild, []*pantry.Recipe{rec("b"), rec("a")}, "p", "1.0", tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if swapped == two {
		t.Error("the order of the halves did not move the hash")
	}
}

// ⛔ A RECIPE THAT CANNOT BE SERIALISED IS AN ERROR, NOT A SKIPPED HALF. A
// project silently hashed over fewer of its halves than the closure read is
// the defect this function exists to avoid — and it would produce a
// confident, wrong hash rather than a failure.
func TestARecipeThatCannotBeSerialisedIsAnError(t *testing.T) {
	bad := &pantry.Recipe{Versions: map[string]any{"ch": make(chan int)}}
	_, err := Hash(DomainBuild, []*pantry.Recipe{rec("a"), bad}, "acme.org/tool", "1.0", tgt, nil)
	if err == nil {
		t.Fatal("an unserialisable recipe hashed cleanly")
	}
	// It names WHICH half and WHICH project, because a build fails over this
	// and the message is all the operator gets.
	for _, want := range []string{"recipe half 1", "acme.org/tool"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
}

// The shape callers rely on: a "sha256:" prefix and a full hex digest, so a
// value can be told from a short form at a glance.
func TestTheHashIsPrefixedAndFullLength(t *testing.T) {
	h, err := Hash(DomainBuild, []*pantry.Recipe{rec("a")}, "p", "1.0", tgt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("hash = %q, want a sha256: prefix", h)
	}
	if len(h) != len("sha256:")+64 {
		t.Errorf("hash = %q (%d chars), want a full hex digest", h, len(h))
	}
}
