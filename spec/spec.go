// Package spec computes the identity of a build: what a bottle IS, as
// opposed to what it is called.
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
// different package. Versions alone call those two builds the same, which is
// the thing an identity exists not to do.
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
// two different spellings hashes alike, and that is deliberate: an identity
// that moved on whitespace would be re-taken until it stopped meaning
// anything.
//
// # WHY IT LIVES HERE AND NOT IN cmd/zpkb
//
// It was written for `zpkb lock` and sat in `package main`, where the BUILD
// could not reach it — so the factory shipped 42 756 bottles with no identity
// at all while a correct one sat two directories away (go-zpkg/zpkb#410). A
// hash that only one command can compute is a hash the product does not have.
package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// Domains are the hash's first line, and two different questions must not
// share one.
//
// ⛔ A DOMAIN IS NOT DECORATION. `lock` identifies a dependency by its own
// SPEC HASH, because it holds the whole closure's recipes; a BUILD identifies
// one by its resolved store PREFIX, because that is what it has and because a
// hashed prefix already carries the dependency's identity — the same trick
// Nix uses when a derivation references its inputs by store path. Those are
// different functions of different inputs. Hashing them under one domain
// would let a value computed for one be compared against the other, and the
// comparison would be meaningless rather than wrong-looking.
const (
	// DomainLock is `zpkb lock`'s. ⛔ THE STRING IS FROZEN: every lock file
	// ever written contains hashes computed under it, and `lock --check`
	// compares them. Changing it invalidates every lock in existence.
	DomainLock = "bk-lock-spec-hash v1"
	// DomainBuild is the identity a bottle is built and published under.
	DomainBuild = "zpkb-build-spec-hash v1"
)

// Hash is a Merkle hash over a project AS RESOLVED: its platform, its name,
// the version it resolved to, the content of the recipe (or recipes) that
// describe it, and an identity for each dependency.
//
// # BOTH HALVES, BECAUSE THE CLOSURE READS BOTH
//
// A project can be described by the pantry AND by our overlay, and both are
// passed because they say different things. The hash covers both, in the
// order the closure reads them: a hash taken over one half would describe a
// different graph from the one beside it.
//
// # depIDs
//
// Already formatted by the caller as "<name> <identity>", sorted, because
// what identifies a dependency differs by question — see Domain.
func Hash(domain string, recs []*pantry.Recipe, proj, version string, tgt target.Target, depIDs []string) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", domain)
	fmt.Fprintf(h, "platform %s/%s\n", tgt.Platform, tgt.Arch)
	fmt.Fprintf(h, "project %s\n", proj)
	fmt.Fprintf(h, "version %s\n", version)
	if err := hashRecipes(h, recs, proj); err != nil {
		return "", err
	}
	for _, d := range depIDs {
		fmt.Fprintf(h, "dep %s\n", d)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func hashRecipes(h io.Writer, recs []*pantry.Recipe, proj string) error {
	for i, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			// Not swallowed: a recipe that cannot be serialised has no hash,
			// and a project silently hashed over fewer of its halves than the
			// closure read is the defect this function exists to avoid.
			return fmt.Errorf("recipe half %d of %s: %w", i, proj, err)
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(h, "recipe %d %s\n", i, hex.EncodeToString(sum[:]))
	}
	return nil
}

// ⛔ THE SHORT FORM IS bottle.ShortHash's, AND IS NOT DUPLICATED HERE. A
// store path and an OCI tag have to agree on it, and `bottle` is what writes
// both. An OCI tag may hold `[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}` and no `:`,
// so the raw "sha256:…" cannot be a tag at all — the caller shortens.
