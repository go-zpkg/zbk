package build

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// concreteOf describes what this build IS, in the form the artifact carries and
// a reader can verify: `artifact.Concrete`.
//
// ⛔⛔ THERE IS ONE DEFINITION OF A BUILD'S IDENTITY AND IT LIVES IN `artifact`.
// This function used to compute a second one, `spec.Hash(spec.DomainBuild,…)`,
// and put its short form in the install prefix. That was wrong in a way that
// would only have surfaced after publishing: `artifact.VerifySpec` checks that
// the spec on a manifest hashes to the hash in the tag, so a tag carrying our
// number and an annotation carrying artifact's would have made every artifact we
// publish fail its own verification — and the message says "the artifact does
// not match its own description", which reads as tampering.
//
// It was also the weaker of the two. A hash is only worth what a reader can
// recompute, and nothing published carries the inputs to `spec.Hash`: the
// annotation holds the platform, the resolved closure and a recipe DIGEST, so
// `Concrete.Hash()` can be recomputed from the artifact and ours could not.
// `spec` remains what it was written for, `zpkb lock`, whose domain string is
// frozen into every lock file in existence.
//
// ⛔ DEPENDENCIES ARE IDENTIFIED BY THEIR OWN HASH, WHICH MAKES THIS MERKLE.
// The hash comes out of the resolved prefix — `…/openssl.org/v3.6.4-h<hash>`
// — so hashing the edge carries the dependency's whole identity with it,
// transitively, the way a Nix derivation references its inputs by store path.
// A dependency still installed at an unhashed `v<version>` contributes an
// empty hash: that edge degrades to version-level precision and no further,
// and it repairs itself as the registry is rebuilt. Said out loud rather than
// hidden, because a hash is only as sharp as what it is taken over.
func concreteOf(recipe *pantry.Recipe, tgt target.Target, deps []moustache.Dep) (artifact.Concrete, error) {
	dig, err := recipeDigest(recipe)
	if err != nil {
		return artifact.Concrete{}, err
	}
	c := artifact.Concrete{
		Platform: tgt.Platform + "/" + tgt.Arch,
		Recipe:   dig,
	}
	for _, d := range deps {
		c.Deps = append(c.Deps, artifact.Dep{
			Project: d.Project,
			Version: d.Version,
			Hash:    hashOfPrefix(d.Path),
		})
	}
	// Sorted, because this comes from walking a map and a hash that depended
	// on the order a map was walked would differ between two runs of the same
	// build — the one thing an identity must never do. Canonical() sorts its
	// own fields; this keeps the slice itself stable for everything else that
	// reads a Concrete, including the annotation a reader diffs by eye.
	sort.Slice(c.Deps, func(i, j int) bool {
		if c.Deps[i].Project != c.Deps[j].Project {
			return c.Deps[i].Project < c.Deps[j].Project
		}
		return c.Deps[i].Version < c.Deps[j].Version
	})
	return c, nil
}

// recipeDigest is the digest of the build PLAN, which is what Concrete.Recipe
// is contractually owed — never of the recipe file's bytes.
//
// ⛔ OVER THE PARSED VALUE RE-SERIALISED, so reformatting a recipe, reordering
// its mapping keys or rewriting its comments does not move it, and changing
// what it says does. Hashing the file instead would make a reflowed comment
// rebuild the world: every dependent's hash moves, every artifact is
// republished, and no binary differs. Spack strips comments and docstrings
// from package.py before hashing for the same reason, and Nix hashes the
// instantiated derivation rather than the expression.
func recipeDigest(recipe *pantry.Recipe) (string, error) {
	b, err := json.Marshal(recipe)
	if err != nil {
		// Not swallowed. A recipe that cannot be serialised has no digest, and
		// a build hashed over less than the recipe says is the defect the
		// digest exists to prevent.
		return "", fmt.Errorf("canonical recipe: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// hashOfPrefix reads a dependency's own identity out of the prefix it resolved
// to. "" when that prefix names a version and not a build — an older install,
// or one made before the layout carried the hash.
func hashOfPrefix(path string) string {
	if path == "" {
		return ""
	}
	v, ok := artifact.ParseStoreDirName(filepath.Base(path))
	if !ok {
		return ""
	}
	return v.Variant
}
