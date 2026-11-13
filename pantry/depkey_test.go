package pantry

import (
	"fmt"
	"strings"
	"testing"
)

// recipeWithDep is the smallest recipe the schema accepts, with one
// dependency key substituted in.
func recipeWithDep(key string) []byte {
	return fmt.Appendf(nil, `distributable:
  url: https://example.com/v{{version}}.tgz
versions:
  - 1.0
dependencies:
  %s: "*"
build:
  script:
    - make
`, key)
}

// ⛔ A DEPENDENCY KEY BECOMES A REGISTRY REPOSITORY AND A STORE PATH.
//
// bk reads the UPSTREAM pantry — a third-party checkout — takes these keys
// out of it and concatenates them into a URL (OCIClient.repository) and a
// filesystem path (InstallFor builds <dir>/<project>/v<version>, written to).
// artifact validates at both of those; `git grep ValidateProjectName` in bk
// returns nothing, so until now nothing here constrained the shape at all.
//
// The constraint lives in the authoritative schema rather than in Go because
// that is what this package calls authoritative, and because the HCL2
// front-end decodes into the same Recipe and would otherwise need its own
// copy of the rule.
//
// ⛔ Measured before it was added: the upstream pantry's 1929 recipes carry
// 7410 dependency-map keys across both levels, and the pattern accepts every
// one. A constraint on the authoritative schema that rejected something real
// would not be a tightening, it would be an outage.
func TestADependencyKeyMustBeAUsableName(t *testing.T) {
	for _, c := range []struct{ what, key string }{
		{"a traversal", `"../../etc/passwd"`},
		{"a bare parent", `".."`},
		{"a single dot", `"."`},
		{"a parent as one segment of several", `"a/../b"`},
		{"an absolute path", `"/etc"`},
		{"a trailing slash, which leaves an empty segment", `"gnu.org/"`},
		{"a doubled slash", `"gnu.org//gcc"`},
		{"a space", `"bad name"`},
		{"a quote", `"a\"b"`},
		{"a newline", `"a\nb"`},
		{"empty", `""`},
	} {
		if err := Validate(recipeWithDep(c.key)); err == nil {
			t.Errorf("a dependency key with %s (%s) was accepted", c.what, c.key)
		}
	}

	// ⛔ THE CONTROL, and it is the half that matters most: the schema nests
	// PLATFORM keys in the same map as project names, so a pattern that only
	// admitted project names would reject `darwin/aarch64` and break every
	// platform-scoped dependency in the pantry.
	for _, key := range []string{
		"gnu.org/gcc",
		"crates.io/semverator",
		"openssl.org",
		"github.com/GoogleContainerTools/container-structure-test",
		"linux",
		"darwin/aarch64",
		"x86-64",
		"freedesktop.org/pkg-config",
		"pkgx.sh",
		"c-ares.org",
		"oracle.com/berkeley-db",
	} {
		if err := Validate(recipeWithDep(key)); err != nil {
			t.Errorf("a real dependency key %q was refused: %v", key, err)
		}
	}
}

// A name longer than the store or a registry will take is refused by length
// rather than by shape, so the error says which rule was broken.
func TestADependencyKeyIsBounded(t *testing.T) {
	long := strings.Repeat("a", 201)
	if err := Validate(recipeWithDep(long)); err == nil {
		t.Errorf("a %d-character dependency key was accepted", len(long))
	}
	if err := Validate(recipeWithDep(strings.Repeat("a", 200))); err != nil {
		t.Errorf("a 200-character key is within the bound and was refused: %v", err)
	}
}

// ⛔ A RECIPE IS SOMEBODY ELSE'S FILE. Parse reads the upstream pantry, so
// the property worth a fuzz target is not "does not panic" but: whatever
// gets PAST the parser can be used as the things the caller will use it as.
// bk had no fuzz targets anywhere before this file and the two in logical/.
func FuzzParseDependencyKeys(f *testing.F) {
	f.Add(string(recipeWithDep("openssl.org")))
	f.Add(string(recipeWithDep(`"../../etc/passwd"`)))
	f.Add(string(recipeWithDep(`"darwin/aarch64"`)))
	f.Add("dependencies:\n  linux:\n    gnu.org/gcc: 14\n")
	f.Add("versions:\n  - 1.0\n")
	f.Add("")
	f.Add("{")
	f.Fuzz(func(t *testing.T, src string) {
		if err := Validate([]byte(src)); err != nil {
			return // refused by the authoritative schema, which is the contract
		}
		rec, err := Parse([]byte(src))
		if err != nil || rec == nil {
			return
		}
		// Anything that got past Validate has keys the schema admits, so no
		// key may hold a path segment that escapes, at either level.
		for _, m := range []map[string]any{rec.Dependencies, buildDepsOf(rec)} {
			for k, v := range m {
				mustBeUsableKey(t, src, k)
				if sub, ok := v.(map[string]any); ok {
					for k2 := range sub {
						mustBeUsableKey(t, src, k2)
					}
				}
			}
		}
	})
}

func mustBeUsableKey(t *testing.T, src, k string) {
	t.Helper()
	if k == "" {
		t.Fatalf("an empty dependency key survived validation of %q", src)
	}
	for _, seg := range strings.Split(k, "/") {
		switch seg {
		case "", ".", "..":
			t.Fatalf("dependency key %q has a %q segment, and becomes a store path, in %q", k, seg, src)
		}
	}
}

func buildDepsOf(rec *Recipe) map[string]any {
	b, ok := rec.Build.(map[string]any)
	if !ok {
		return nil
	}
	d, _ := b["dependencies"].(map[string]any)
	return d
}
