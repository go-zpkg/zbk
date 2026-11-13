package main

import (
	"sort"
	"strings"

	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/spec"
	"github.com/go-zpkg/zpkb/target"
)

// specHash is a Merkle hash over a project AS RESOLVED: its platform, its
// name, the version it resolved to, the content of the recipe (or recipes)
// that describe it, and the hashes of its dependencies.
//
// # WHOSE IDEA THIS IS
//
// Spack's, exactly. Its packaging guide states what goes into a spec hash:
// "build, link, and run dependencies all affect the hash of Spack packages
// (along with sha256 sums of patches and archives used to build the package,
// and a canonical hash of the package.py recipes)".
//
// The part worth copying is the last clause. Pinning versions catches an
// upstream that moved; hashing the RECIPE catches the other half — a build
// script edited in the pantry resolves to the same version and produces a
// different package. A lock with versions alone calls those two builds the
// same, which is the thing a lock exists not to do.
//
// # WHAT "CANONICAL" MEANS HERE, AND WHAT IT DOES NOT
//
// Spack canonicalises package.py's AST, dropping comments and docstrings.
// Here the recipe is parsed YAML or HCL, and the hash is taken over the
// PARSED value re-serialised as JSON with sorted keys. So reformatting a
// recipe, reordering its mapping keys or rewriting its comments does not
// move the hash, and changing what it says does.
//
// It is NOT a hash of the file. A recipe whose meaning is identical through
// two different spellings hashes alike, and that is deliberate: a lock that
// invalidated on whitespace would be re-taken until it stopped meaning
// anything.
//
// # BOTH HALVES, BECAUSE THE CLOSURE READS BOTH
//
// A project can be described by the pantry AND by our overlay, and
// closureRecipes returns both because they say different things. The hash
// covers both, in the order the closure reads them: a hash taken over one
// half would describe a different graph from the one beside it in the same
// file.
// ⛔ THE CANONICAL FORM MOVED TO zpkb/spec, AND THE BYTES DID NOT. This now
// formats the dependency identities and delegates; the domain line, the
// field order and the recipe hashing are the ones every existing lock file
// was written with, so `lock --check` still compares like with like. The
// reason it moved is that it sat in `package main`, where the BUILD could not
// reach it — so the factory published 42 756 bottles with no identity while a
// correct one sat two directories away (go-zpkg/zpkb#410).
func specHash(recs []*pantry.Recipe, proj, version string, tgt target.Target, depHashes map[string]string, deps []string) (string, error) {
	ids := make([]string, 0, len(deps))
	for _, d := range deps {
		dh, ok := depHashes[d]
		if !ok {
			// A dependency the closure could not read — it resolves from the
			// upstream dist at build time — is recorded as unknown rather than
			// omitted. Omitting it would make "we have no recipe for X" and "X
			// is not a dependency" hash alike; and the day a recipe for it
			// arrives, the hash must move.
			dh = "(no recipe)"
		}
		ids = append(ids, d+" "+dh)
	}
	return spec.Hash(spec.DomainLock, recs, proj, version, tgt, ids)
}

// specDeps is the sorted, de-duplicated set of dependency NAMES across every
// half of a recipe, for tgt. It is the same reduction closureOf walks, so the
// hash describes the graph the lock lists and not a neighbouring one.
func specDeps(recs []*pantry.Recipe, tgt target.Target) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range recs {
		for _, spec := range build.DepSpecs(r.Dependencies, tgt) {
			n := depName(spec)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// shortHash is the first 12 hex digits, the length git settled on for a
// human-readable prefix. The full hash is what is compared; this is what is
// printed when a line has to fit on a screen.
func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
