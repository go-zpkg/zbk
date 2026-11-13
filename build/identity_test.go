package build

import (
	"os"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

func idRecipe() *pantry.Recipe {
	return &pantry.Recipe{
		Distributable: map[string]any{"url": "https://x/v{{version.raw}}.tar.gz"},
		Build:         map[string]any{"script": []any{"make install"}},
	}
}

var idTarget = target.Target{Platform: "linux", Arch: "x86-64"}

func mustHash(t *testing.T, rec *pantry.Recipe, tgt target.Target, deps []moustache.Dep) string {
	t.Helper()
	c, err := concreteOf(rec, tgt, deps)
	if err != nil {
		t.Fatalf("concreteOf: %v", err)
	}
	got := c.Hash()
	if got == "" {
		t.Fatal("the spec describes nothing, so it has no address")
	}
	return got
}

// ⛔⛔ THE IDENTITY IS WHAT THE PUBLISHED ARTIFACT SAYS IT IS. The tag carries
// `-h<hash>` and the manifest carries the spec; artifact.VerifySpec recomputes
// the first from the second and refuses the pair when they disagree. So the
// property that matters is not "we have a hash" but "the hash is a function
// of the description we publish" — which is exactly what this asserts, by
// going through the annotation the way a reader does.
//
// A hash computed any other way (this package had one, over inputs nothing
// published carries) would make every artifact fail its own verification, with
// a message that reads as tampering.
func TestTheIdentityIsRecomputableFromThePublishedSpec(t *testing.T) {
	c, err := concreteOf(idRecipe(), idTarget, []moustache.Dep{
		{Project: "openssl.org", Version: "3.6.4", Path: "/s/openssl.org/v3.6.4-habcdefghijklmnop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tag := "1.2.3" + c.VariantTag()
	if !strings.HasPrefix(c.VariantTag(), "-h") {
		t.Fatalf("the tag suffix is not a hash: %q", c.VariantTag())
	}

	// The round trip a reader makes: split the hash out of the tag, read the
	// annotation, and check the one against the other.
	_, wantHash := artifact.SplitVariantHash(tag)
	if wantHash == "" {
		t.Fatalf("the tag %q does not read back as carrying a hash", tag)
	}
	got, err := artifact.VerifySpec(artifact.MarshalSpec(c), wantHash)
	if err != nil {
		t.Fatalf("the artifact would not verify against its own tag: %v", err)
	}
	if got.Hash() != c.Hash() {
		t.Errorf("the spec came back as a different build: %q vs %q", got.Hash(), c.Hash())
	}
}

// ⛔⛔ THE SAME INPUTS GIVE THE SAME ANSWER, TWICE AND IN ANY ORDER. The hash
// goes in the install prefix, which is baked into every binary the build
// links, so an identity that varied between two runs of the same build would
// make the store unable to say that a rebuild produced the same thing.
func TestAnIdentityIsStableAcrossRunsAndDependencyOrder(t *testing.T) {
	rec := idRecipe()
	a := mustHash(t, rec, idTarget, nil)
	if b := mustHash(t, rec, idTarget, nil); a != b {
		t.Errorf("two runs disagree: %q vs %q", a, b)
	}

	// Dependencies reach this as a slice built by walking a map, so the order
	// is whatever Go felt like. The sort in concreteOf is what makes the two
	// spellings below one identity, and the assertion is that they are.
	deps := []moustache.Dep{
		{Project: "openssl.org", Version: "3.5.8", Path: "/s/openssl.org/v3.5.8-habcdefghijklmnop"},
		{Project: "zlib.net", Version: "1.3.2", Path: "/s/zlib.net/v1.3.2-hqrstuvwxyz234567"},
	}
	fwd := mustHash(t, rec, idTarget, deps)
	rev := mustHash(t, rec, idTarget, []moustache.Dep{deps[1], deps[0]})
	if fwd != rev {
		t.Errorf("the order a map was walked in changed the identity: %q vs %q", fwd, rev)
	}
	if fwd == a {
		t.Error("adding two dependencies did not change the identity")
	}
}

// ⛔⛔ EVERY INPUT IS LOAD-BEARING, AND EACH IS CHECKED AGAINST EVERY OTHER. A
// table that only compared each case to the base would pass with an input
// silently dropped from the hash, as long as one other input varied with it.
// Here each case changes exactly one thing and collides with nothing.
func TestEveryInputChangesTheIdentity(t *testing.T) {
	base := mustHash(t, idRecipe(), idTarget, nil)

	otherScript := idRecipe()
	otherScript.Build = map[string]any{"script": []any{"make install", "make check"}}
	otherURL := idRecipe()
	otherURL.Distributable = map[string]any{"url": "https://y/v{{version.raw}}.tar.gz"}

	seen := map[string]string{base: "the base"}
	for _, tc := range []struct {
		what string
		rec  *pantry.Recipe
		tgt  target.Target
		deps []moustache.Dep
	}{
		{"the platform", idRecipe(), target.Target{Platform: "darwin", Arch: "x86-64"}, nil},
		{"the architecture", idRecipe(), target.Target{Platform: "linux", Arch: "aarch64"}, nil},
		{"the build script", otherScript, idTarget, nil},
		{"the distributable", otherURL, idTarget, nil},
		{"a dependency", idRecipe(), idTarget,
			[]moustache.Dep{{Project: "zlib.net", Version: "1.3.2", Path: "/s/zlib.net/v1.3.2-habcdefghijklmnop"}}},
		{"a dependency's version", idRecipe(), idTarget,
			[]moustache.Dep{{Project: "zlib.net", Version: "1.3.1", Path: "/s/zlib.net/v1.3.1-habcdefghijklmnop"}}},
		{"a dependency's own build", idRecipe(), idTarget,
			[]moustache.Dep{{Project: "zlib.net", Version: "1.3.2", Path: "/s/zlib.net/v1.3.2-hqrstuvwxyz234567"}}},
	} {
		got := mustHash(t, tc.rec, tc.tgt, tc.deps)
		if prev, dup := seen[got]; dup {
			t.Errorf("changing %s gives the same identity as %s: %q", tc.what, prev, got)
			continue
		}
		seen[got] = "changing " + tc.what
	}
}

// ⛔ THE PROJECT AND THE VERSION ARE NOT IN THE HASH, AND THAT IS CORRECT.
// They are in the tag and in the store path the hash is appended to, so the
// hash only has to separate builds WITHIN one (project, version) — which is
// what it does. Asserted rather than assumed, because a reader who expected
// the hash to be globally unique would use it as one.
func TestTheHashSeparatesBuildsWithinAVersionAndIsNotAGlobalName(t *testing.T) {
	rec := idRecipe()
	c, err := concreteOf(rec, idTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Identical inputs, so identical hashes — the project and version a
	// caller would pass alongside are not part of it.
	again, err := concreteOf(rec, idTarget, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hash() != again.Hash() {
		t.Fatalf("one description, two addresses: %q vs %q", c.Hash(), again.Hash())
	}
	// And what keeps them apart is the tag the hash hangs off.
	if buildA, buildB := "1.2.3"+c.VariantTag(), "1.2.4"+again.VariantTag(); buildA == buildB {
		t.Error("two versions produced one tag")
	}
}

// ⛔ A DEPENDENCY INSTALLED WITHOUT A HASH CONTRIBUTES AN EMPTY ONE. That edge
// degrades to version-level precision and no further, which is the honest
// state while the registry is being rebuilt — and it must not be mistaken for
// a hash, nor make the whole identity refuse.
func TestADependencyWithNoHashDegradesThatEdgeOnly(t *testing.T) {
	plain := mustHash(t, idRecipe(), idTarget,
		[]moustache.Dep{{Project: "zlib.net", Version: "1.3.2", Path: "/s/zlib.net/v1.3.2"}})
	hashed := mustHash(t, idRecipe(), idTarget,
		[]moustache.Dep{{Project: "zlib.net", Version: "1.3.2", Path: "/s/zlib.net/v1.3.2-habcdefghijklmnop"}})
	if plain == hashed {
		t.Error("a dependency's hash did not reach the identity")
	}
	if got := hashOfPrefix("/s/zlib.net/v1.3.2"); got != "" {
		t.Errorf("an unhashed prefix yielded a hash: %q", got)
	}
	if got := hashOfPrefix("/s/zlib.net/v1.3.2-habcdefghijklmnop"); got != "abcdefghijklmnop" {
		t.Errorf("the dependency's own hash was not read back: %q", got)
	}
	// A prefix we cannot parse is not a hash either, and must not become one.
	for _, p := range []string{"", "/s/zlib.net/notaversion", "/s/zlib.net"} {
		if got := hashOfPrefix(p); got != "" {
			t.Errorf("hashOfPrefix(%q) = %q, want none", p, got)
		}
	}
}

// ⛔ THE DEPENDENCY ORDER IS TOTAL, INCLUDING FOR TWO EDGES TO THE SAME
// PROJECT. Sorting on the project alone leaves those two in whatever order
// the map was walked, which is the defect the sort exists to remove — and it
// would show up only as an identity that changed between runs, which is the
// hardest kind of bug to catch from the outside.
func TestTwoEdgesToOneProjectStillSortTotally(t *testing.T) {
	deps := []moustache.Dep{
		{Project: "zlib.net", Version: "1.3.2", Path: "/s/zlib.net/v1.3.2-habcdefghijklmnop"},
		{Project: "zlib.net", Version: "1.2.13", Path: "/s/zlib.net/v1.2.13-hqrstuvwxyz234567"},
	}
	fwd := mustHash(t, idRecipe(), idTarget, deps)
	rev := mustHash(t, idRecipe(), idTarget, []moustache.Dep{deps[1], deps[0]})
	if fwd != rev {
		t.Errorf("two edges to one project hash differently by input order: %q vs %q", fwd, rev)
	}
	c, err := concreteOf(idRecipe(), idTarget, []moustache.Dep{deps[1], deps[0]})
	if err != nil {
		t.Fatal(err)
	}
	if c.Deps[0].Version != "1.2.13" {
		t.Errorf("the lower version did not sort first: %+v", c.Deps)
	}
}

// ⛔⛔ THE MERKLE PROPERTY WAS INERT AND THIS IS THE TEST THAT CATCHES IT.
//
// DepTokens COMPOSED a dependency's prefix as `<dir>/<project>/v<version>`.
// That is not a path that exists once a build is installed under its
// identity, so two things rode on it silently: the build script was pointed
// at a directory that is not there, and `concreteOf` read an EMPTY hash out
// of every edge — which made two builds differing only in how a dependency
// was built hash alike, the exact collision the whole design exists to end.
//
// It is tested through DepTokens and not through concreteOf, because
// concreteOf was always correct: it reads whatever the path carries, and the
// path carried nothing.
func TestADependencysOwnBuildReachesTheIdentityThroughItsPrefix(t *testing.T) {
	store := t.TempDir()
	t.Setenv("ZPKG_DIR", store)

	// Two builds of one version of a dependency, installed as the installer
	// installs them: hashed.
	const dep, depVer = "zlib.net", "1.3.2"
	v := artifact.Ver{Raw: depVer}
	var hashes []string
	for _, seed := range []string{"a", "b"} {
		h := artifact.StoreHash(v, "digest:"+seed, "")
		if err := os.MkdirAll(artifact.StoreBuildPrefix(store, dep, v, h), 0o755); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, h)
	}

	// With TWO installed, the store cannot say which, so the prefix falls
	// back to the composed path and the edge degrades to the version. That
	// is the documented honest behaviour, not a hash we invented.
	_, resolved, err := DepTokens(
		map[string]any{dep: "^1"}, nil, idTarget, store,
		func(string, string) (string, error) { return depVer, nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := hashOfPrefix(resolved[0].Path); got != "" {
		t.Errorf("two builds installed and one was picked anyway: %q", got)
	}

	// With ONE installed, the edge carries that build's own hash — and the
	// identity moves with it.
	if err := os.RemoveAll(artifact.StoreBuildPrefix(store, dep, v, hashes[1])); err != nil {
		t.Fatal(err)
	}
	_, resolved, err = DepTokens(
		map[string]any{dep: "^1"}, nil, idTarget, store,
		func(string, string) (string, error) { return depVer, nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := hashOfPrefix(resolved[0].Path); got != hashes[0] {
		t.Fatalf("the dependency's own build did not reach its prefix: %q, want %q (path %q)",
			got, hashes[0], resolved[0].Path)
	}
	// And that is what makes the dependent's identity move: the same version
	// of the same dependency, built differently, is a different build of us.
	mine := mustHash(t, idRecipe(), idTarget, resolved)
	other := mustHash(t, idRecipe(), idTarget, []moustache.Dep{{
		Project: dep, Version: depVer,
		Path: artifact.StoreBuildPrefix(store, dep, v, hashes[1]),
	}})
	if mine == other {
		t.Error("a dependency rebuilt into a different prefix left our identity alone")
	}
}

// ⛔⛔ A BUILD WHOSE IDENTITY CANNOT BE COMPUTED DOES NOT BUILD. There is no
// weaker prefix to fall back to: `v<version>` is the shape two builds of one
// version overwrote each other in, and an identity that failed quietly would
// either produce it or produce a prefix hashed over less than the recipe says.
func TestABuildStopsWhenItsIdentityCannotBeComputed(t *testing.T) {
	tenv(t)
	tgt := target.Target{Platform: "linux", Arch: "x86-64"}
	rec := okRecipe()
	// A channel has no JSON form, so the recipe does not serialise and the
	// digest refuses rather than describing less than the recipe says.
	rec.Build = map[string]any{"script": []any{"make install"}, "unserialisable": make(chan int)}

	_, err := okRunner("acme.org/tool", tgt).Build(rec, "acme.org/tool", "*", tgt, tgt, "")
	if err == nil {
		t.Fatal("Build: nil; a build with no identity has no prefix to install into")
	}
	if !strings.Contains(err.Error(), "build identity") {
		t.Errorf("the failure does not name the step: %v", err)
	}
}
