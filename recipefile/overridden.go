package recipefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/logical"
	"github.com/go-zpkg/zbk/pantry"
	"gopkg.in/yaml.v3"
)

// yamlMarshal is a seam. Marshalling a document a parser produced cannot
// realistically fail — every value in it came out of a decoder — but the error
// exists and swallowing it would mean feeding the schema an empty recipe.
var yamlMarshal = yaml.Marshal

// LoadOverridden reads a recipe and applies the project's LOGICAL override, if
// the set holds one.
//
// Nothing on disk is touched. The unified diffs this is replacing were applied
// by rewriting package.yml in the pantry checkout, which worked because a
// textual diff leaves alone everything it does not mention; a document rewrite
// would drop every comment in the file, and those comments carry the reasons —
// gnu.org/grep spends thirteen lines explaining why it names itself as a build
// dependency.
//
// A project the set does not mention takes exactly the path it took before:
// same bytes, same front-end, no document round trip. During the migration
// most projects are still unified diffs and must not change behaviour because
// this function exists.
func LoadOverridden(set *logical.Set, pantryDir, project string) (*pantry.Recipe, error) {
	r, _, err := LoadOverriddenReporting(set, pantryDir, project)
	return r, err
}

// LoadOverriddenReporting is LoadOverridden, saying what each operation did.
//
// `bk overrides` needs the outcomes — applied, already true, premise gone —
// and getting them by applying the override a SECOND time next to this call
// left two error branches no input could reach, because anything that fails
// there has already failed here. One read, one application, one answer.
func LoadOverriddenReporting(set *logical.Set, pantryDir, project string) (*pantry.Recipe, []logical.Result, error) {
	dir := Dir(pantryDir, project)
	for _, n := range Names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if set.For(project) == nil {
			r, err := parse(b, n)
			return r, nil, err
		}
		return overridden(set, project, b, n)
	}
	return nil, nil, fmt.Errorf("%w for %s in %s (tried %v)", ErrNoRecipe, project, dir, Names)
}

// overridden applies the override between reading the file and validating it,
// so the result goes through the same schema every other recipe does. An
// override that produces something a recipe may not say fails here, loudly,
// rather than at the point the build trips over it.
func overridden(set *logical.Set, project string, b []byte, name string) (*pantry.Recipe, []logical.Result, error) {
	y := b
	if filepath.Ext(name) == ".hcl" {
		// Through bottle, the same converter the client uses: a second reading
		// of one format is two opinions about what a recipe means.
		var err error
		if y, err = bottle.HCLToYAML(b, name); err != nil {
			return nil, nil, err
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal(y, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	res, err := set.ApplyTo(project, doc)
	if err != nil {
		return nil, res, err
	}
	out, err := yamlMarshal(doc)
	if err != nil {
		return nil, res, fmt.Errorf("%s: %w", name, err)
	}
	r, err := pantry.Parse(out)
	return r, res, err
}

// LoadBuildRecipe reads the recipe the FACTORY compiles.
//
// The pantry first, with the project's logical override applied; the overlay
// only when the pantry has no such project at all.
//
// FALLBACK, not preference — and the difference is the whole division of
// labour. For a project upstream carries, `overrides/` fixes the BUILD and the
// overlay fixes what a consumer RESOLVES, and letting the overlay win here
// would silently build something other than what the overrides say. For a
// project upstream does not carry, there is nothing to fall back from: the
// overlay's copy is the only recipe there is.
//
// It replaces a directory of patches that CREATED those recipes. A patch that
// adds a whole package.yml is not an override of anybody's recipe — it is a
// recipe of ours — and writing it twice, once as a diff for the builder and
// once as HCL for the consumer, is the two-halves defect carried deliberately.
// Measured on 2026-09-28: 8 projects were written both ways, and exactly 8 of
// the overlay's 183 are absent upstream, so this reaches those and nothing
// else.
// It returns the DIRECTORY it read from as well as the recipe, because the
// two must not be worked out separately. The factory computed the directory
// as Dir(pantryDir, project) regardless of where the recipe came from, so
// for the eight projects whose recipe exists only in the overlay —
// gnu.org/gzip, openucx.org, kernel.org/linux and five more — it named a
// path that is not there. Nothing broke: none of the eight carries a file
// beside its recipe and none references props/, so the copy copied nothing
// that was wanted. It is the day one of them gains a fixture that the build
// silently loses it, and `bk factory --test-only` already reports
//
//	NOT-RUN gnu.org/gzip 1.15: open pantry/projects/gnu.org/gzip:
//	                           no such file or directory
func LoadBuildRecipe(set *logical.Set, overlayDir, pantryDir, project string) (*pantry.Recipe, string, error) {
	r, err := LoadOverridden(set, pantryDir, project)
	if !errors.Is(err, ErrNoRecipe) || overlayDir == "" {
		return r, Dir(pantryDir, project), err
	}
	r, err = Load(overlayDir, project)
	return r, Dir(overlayDir, project), err
}

// LoadMerged reads the overlay MERGED over the pantry recipe as WE build it —
// upstream's, with the logical overrides applied. With a nil set it is
// bottle.recipeDoc exactly, which is what a consumer resolves.
//
// Not the overlay preferred whole. That was right while every overlay entry
// was a full copy of an upstream recipe, and it broke the day they stopped
// being: go-zpkg/pantry-overlay reduced its 183 entries to the keys they
// change (go-zpkg/bottle#103), so reading one on its own gives a fragment.
// Measured before this existed — `bk closure --build curl.se` went from 54
// projects to 8, because the entry says `dependencies` and nothing else, and
// the walk never saw upstream's build dependencies at all.
//
// bottle merges and bk did not, which is the two-halves defect one more time:
// a change landed in the half a consumer reads and the builder's own reader
// kept the old rule.
//
// The set is the second half of the same lesson. The overlay carries 183
// projects and the overrides describe 206, 178 of which edit a dependency, so
// a walk that took the overlay's view for the OTHERS read them unoverridden.
// Measured 2026-09-28 on a pristine pantry: `bk closure --build
// rsync.samba.org` lists gnu.org/libidn2 without --overlay and not with it,
// because that dependency exists only in our override and rsync is one of the
// six such projects the overlay does not carry. The order that misses a
// provider is the order the seed builds.
func LoadMerged(set *logical.Set, overlayDir, pantryDir, project string) (*pantry.Recipe, error) {
	over, hasOver, err := sideDoc(overlayDir, project)
	if err != nil {
		return nil, err
	}
	base, hasBase, err := sideDoc(pantryDir, project)
	if err != nil {
		return nil, err
	}
	if hasBase {
		if _, err := set.ApplyTo(project, base); err != nil {
			return nil, fmt.Errorf("%s: %w", project, err)
		}
	}
	switch {
	case hasBase && hasOver:
		return docRecipe(mergeRecipe(base, over), project)
	case hasOver:
		// Upstream carries no such project: the overlay is the whole recipe.
		return docRecipe(over, project)
	case hasBase:
		return docRecipe(base, project)
	}
	return nil, fmt.Errorf("%w for %s in %s or %s", ErrNoRecipe, project, overlayDir, pantryDir)
}

// sideDoc reads one tree's copy as a document, reporting separately whether it
// is there and whether reading it failed. A recipe that EXISTS and does not
// parse is never silently skipped: the walk would plan a build around
// something it could not read.
//
// ⛔ IT CONVERTS HCL WITH bottle's CONVERTER, NOT OURS, AND THAT IS DELIBERATE.
// What this document is for is the merge below, and mergeRecipe is bottle's
// rule because two readers of one overlay that merged differently would
// describe two different recipes. The reader has to match for the same reason
// the rule does. LoadWithDoc answers a different question and reads with the
// front-end `parse` uses; see its comment.
func sideDoc(dir, project string) (map[string]any, bool, error) {
	if dir == "" {
		return nil, false, nil
	}
	for _, n := range Names {
		b, err := os.ReadFile(filepath.Join(Dir(dir, project), n))
		if err != nil {
			continue
		}
		y := b
		if filepath.Ext(n) == ".hcl" {
			if y, err = bottle.HCLToYAML(b, n); err != nil {
				return nil, false, fmt.Errorf("%s/%s: %w", project, n, err)
			}
		}
		var doc map[string]any
		if err := yaml.Unmarshal(y, &doc); err != nil {
			return nil, false, fmt.Errorf("%s/%s: %w", project, n, err)
		}
		return doc, true, nil
	}
	return nil, false, nil
}

// mergeRecipe is bottle's rule, and it has to be: two readers of one overlay
// that merged differently would describe two different recipes. A key the
// overlay states replaces that key, a key it omits is inherited, and a list
// replaces rather than merges.
func mergeRecipe(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if om, ok := v.(map[string]any); ok {
			if bm, ok2 := out[k].(map[string]any); ok2 {
				out[k] = mergeRecipe(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func docRecipe(doc map[string]any, project string) (*pantry.Recipe, error) {
	out, err := yamlMarshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", project, err)
	}
	return pantry.Parse(out)
}
