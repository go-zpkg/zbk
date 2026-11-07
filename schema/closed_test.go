package schema_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/go-zpkg/zbk/pantry"
	"github.com/go-zpkg/zbk/schema"
)

// rootIsOpen reports whether the schema admits unknown keys at the root. It
// reads the schema rather than a constant here, so this file cannot disagree
// with the document it is about.
func rootIsOpen() (bool, error) {
	var doc map[string]any
	if err := json.Unmarshal(schema.PackageJSON, &doc); err != nil {
		return false, err
	}
	v, ok := doc["additionalProperties"]
	if !ok {
		// Absent means true in JSON Schema, which is the open case.
		return true, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("schema: root additionalProperties is %T, not a boolean", v)
	}
	return b, nil
}

// ⛔⛔ A SCHEMA IS ONLY CLOSED IF SOMETHING FAILS WHEN IT IS REOPENED.
// `additionalProperties: false` is one word in a JSON file, and the corpus
// survey next door cannot see it: that test asks which keys a pantry uses,
// not whether the validator would refuse them. Without these cases, flipping
// a `false` back to `true` — or adding a sixth container and forgetting it —
// goes green.
//
// Each case is a recipe that differs from a valid one by exactly one key, so
// a failure names the container that stopped refusing.
//
// ⛔⛔ IT TRACKS THE SCHEMA INSTEAD OF ASSERTING A POLICY. The schema was
// closed in #423 and REOPENED the same day: closing it stopped us reading
// foreign recipes, and the toolchain's own — openssl.org, llvm.org,
// cmake.org, python.org, rust-lang.org — are among them. So this test reads
// the root's `additionalProperties` and skips while it is open, rather than
// failing for a policy nobody has adopted yet. The moment someone closes it
// again, every assertion below comes back without being rewritten.
func TestAnUnknownKeyIsRefused(t *testing.T) {
	if open, err := rootIsOpen(); err != nil {
		t.Fatal(err)
	} else if open {
		t.Skip("the schema is open at the root (additionalProperties: true), so an " +
			"unknown key validates by design — see the reopening in zbk and " +
			"go-zpkg/packages#420, #431. Close it and these cases apply again.")
	}
	const valid = `
distributable:
  url: https://example.org/x-{{version.raw}}.tar.gz
  strip-components: 1
versions:
  github: example/x
build:
  script:
    - make install
provides:
  - bin/x
`
	if err := pantry.Validate([]byte(valid)); err != nil {
		t.Fatalf("the control recipe does not validate, so every case below would "+
			"pass for the wrong reason: %v", err)
	}

	for _, c := range []struct{ what, yaml string }{
		{"root", valid + "\nnosuchkey: 1\n"},
		{"build", `
build:
  script: [make install]
  nosuchkey: 1
`},
		{"test", `
test:
  script: [./x --version]
  nosuchkey: 1
`},
		{"distributable", `
distributable:
  url: https://example.org/x.tar.gz
  nosuchkey: 1
`},
		{"versions", `
versions:
  github: example/x
  nosuchkey: 1
`},
	} {
		err := pantry.Validate([]byte(c.yaml))
		if err == nil {
			t.Errorf("%s: an unknown key validated — that container is open again, "+
				"and a recipe may declare something nothing implements", c.what)
			continue
		}
		if !strings.Contains(err.Error(), "schema validation failed") {
			t.Errorf("%s: refused for the wrong reason: %v", c.what, err)
		}
	}
}

// The two keys enumerated because the code has always honoured them. If
// either is dropped while the schema is closed, every recipe using it stops
// validating — 21 of the upstream corpus for `npm` — so they are pinned.
func TestTheKeysTheCodeHonoursAreAccepted(t *testing.T) {
	for _, c := range []struct{ what, yaml string }{
		{"distributable.sha", `
distributable:
  url: https://example.org/x.tar.gz
  sha: ${{url}}.sha256
`},
		{"versions.npm", `
versions:
  npm: left-pad
`},
		{"distributable.sha256, scalar", `
distributable:
  url: https://example.org/x.tar.gz
  sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
`},
		{"distributable.sha256, keyed by version", `
distributable:
  url: https://example.org/x-{{version.raw}}.tar.gz
  sha256:
    "1.3.1": 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
    "1.3": cc0b4e42510d49c6decd464123ecf3b14ae9b47f9b4ed2ee64893e2d6520a264
`},
	} {
		if err := pantry.Validate([]byte(c.yaml)); err != nil {
			t.Errorf("%s is honoured by the code and refused by the schema: %v", c.what, err)
		}
	}
}

// ⛔ A PIN THAT IS ALMOST A DIGEST IS WORSE THAN NONE: it reads as a control
// and compares against nothing real. The runner checks the shape too
// (build.pinnedDigest), and so does the schema, so a recipe is refused at
// the earliest point rather than at build time on a runner.
// This one does NOT depend on the container being closed: `sha256` is an
// enumerated property with a pattern, so a bad digest is refused whether or
// not unknown keys are admitted beside it.
func TestSomethingShapedLikeADigestButNotOneIsRefused(t *testing.T) {
	for _, c := range []struct{ what, yaml string }{
		{"a checksum URL where a digest belongs", `
distributable:
  url: https://example.org/x.tar.gz
  sha256: https://example.org/x.tar.gz.sha256
`},
		{"uppercase hex", `
distributable:
  url: https://example.org/x.tar.gz
  sha256: 9A93B2B7DFDAC77CEBA5A558A580E74667DD6FEDE4585B91EEFB60F03B72DF23
`},
		{"truncated", `
distributable:
  url: https://example.org/x.tar.gz
  sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df2
`},
		{"a bad digest inside the version map", `
distributable:
  url: https://example.org/x.tar.gz
  sha256:
    "1.3.1": not-a-digest
`},
	} {
		if err := pantry.Validate([]byte(c.yaml)); err == nil {
			t.Errorf("%s validated as a pinned digest", c.what)
		}
	}
}
