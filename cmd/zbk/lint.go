package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/zbk/recipefile"
)

// runLint implements `bk lint`: read every recipe in a pantry checkout and
// say which ones cannot be read.
//
// A pantry recipe is not a build input anyone can retry. A consumer fetches it
// over HTTP while resolving a closure, so a file that does not parse breaks
// every install of that project — silently, for everyone, with no build to go
// red first. That is the failure a pantry repository is uniquely able to
// cause, and the only one this checks for.
//
// It reads them with recipefile.Load, which is the loader the BUILDER uses:
// the same formats, the same schema, the same refusals. The check this
// replaces was a script that re-stated parts of the schema in another
// language, and it could only ever be a second opinion about what a recipe
// means — it went looking for package.yml and reported "the layout changed"
// the day the recipes became HCL, which is the mildest way that kind of
// divergence can present.
func runLint(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("lint", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", ".", "the pantry checkout to read")
	// ⛔⛔ OUR OWN RECIPES DO NOT ALL LIVE UNDER projects/. go-zpkg/packages
	// keeps the platform-specific ones it authored at `wasip1/recipes/<project>`
	// and `windows/recipes/<project>` — 14 recipes this command could not be
	// pointed at, so every question asked of them got the answer a tree with no
	// recipes gets. A sweep that cannot read a corpus reports the same zero as
	// a clean one, and the empty-tree refusal below is the only reason this was
	// a visible failure rather than a silent pass.
	sub := fset.String("subdir", "projects", "the directory under -dir that holds the project tree")
	// ⛔⛔ PER TREE, AND THAT IS THE WHOLE DESIGN. Our recipes are written
	// from each project's own build system, so each must say which files
	// (go-zpkg/packages#431); an upstream recipe has no reason to carry that
	// and never will. Making it a schema requirement would refuse every
	// foreign recipe we still read — which is exactly the mistake that closing
	// `additionalProperties` made earlier today, when the bootstrap
	// toolchain's own recipes became unreadable (#427). A requirement about
	// OUR files belongs to the command that is pointed at our files.
	requireProv := fset.Bool("require-provenance", false,
		"fail a recipe that does not record which of the project's own files its build came from")
	// ⛔⛔ AN OVERLAY ENTRY IS A FRAGMENT, AND A PANTRY CANNOT BE MADE OF
	// FRAGMENTS. go-zpkg/pantry-overlay#50 reduced all 183 entries to the keys
	// they CHANGE, which was right for an overlay: bottle merges it over
	// PantryBase, so an omitted key is inherited from upstream and a small
	// curated tree can correct a stale constraint without forking 1700 files.
	//
	// It is exactly wrong for a pantry. `PantryBase` is still
	// pkgxdev/pantry compiled in (bottle/pkgx.go:68) and the overlay is merged
	// OVER it, so a fragment resolves only because somebody else's recipe is
	// underneath — the recipe we may not copy (go-zpkg/packages#431). Measured
	// here the day this flag was written: of 213 overlay recipes, 15 state a
	// `distributable`. The other 198 cannot build anything alone.
	//
	// So "we own 213 recipes" and "213 recipes of ours would resolve against an
	// empty upstream" are different claims, and only the second is what a
	// sovereign pantry needs. This flag is the difference, and it is per tree
	// for the same reason --require-provenance is: an overlay is ALLOWED to be
	// fragments, right up until it is asked to be the base.
	requireStandalone := fset.Bool("require-standalone", false,
		"fail a recipe that cannot resolve alone — one that needs another recipe merged underneath it")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	root := filepath.Join(*dir, *sub)
	projects, err := lintProjects(root)
	if err != nil {
		fmt.Fprintf(stderr, "lint: %v\n", err)
		return 1
	}
	// An empty tree is a FAILURE, not a pass. A sweep that could not find its
	// corpus reports the same "no problems" as one that read it all, and the
	// one thing that distinguishes them is saying how many were read.
	if len(projects) == 0 {
		fmt.Fprintf(stderr, "lint: no recipe under %s — the layout changed\n", root)
		return 1
	}

	var bad, unrecorded, fragments []string
	for _, proj := range projects {
		// LoadFile on the project's DIRECTORY rather than Load on (dir,
		// project): Load joins `projects/` in, which is right for a pantry and
		// wrong for the two trees of ours that are not laid out that way.
		pdir := filepath.Join(root, filepath.FromSlash(proj))
		r, err := recipefile.LoadFile(pdir)
		if err != nil {
			bad = append(bad, fmt.Sprintf("  %s: %v", proj, err))
			continue
		}
		// A recipe with no distributable packages nothing of its own — a set,
		// or a project whose files come from its dependencies — so there is no
		// build to have derived from anything.
		if *requireProv && r.Provenance == nil && r.Distributable != nil {
			unrecorded = append(unrecorded, "  "+proj)
		}
		if *requireStandalone {
			doc, ok, err := recipefile.DocFile(pdir)
			if err != nil {
				bad = append(bad, fmt.Sprintf("  %s: %v", proj, err))
				continue
			}
			// Unreachable through this loop — recipefile.Load just read the
			// same file — but a missing recipe must never read as a standalone
			// one, so the absence is answered rather than assumed away.
			if !ok {
				bad = append(bad, fmt.Sprintf("  %s: no recipe document", proj))
				continue
			}
			if miss := missingEssentials(doc); len(miss) > 0 {
				fragments = append(fragments, fmt.Sprintf("  %s: states no %s",
					proj, strings.Join(miss, ", no ")))
			}
		}
	}
	fmt.Fprintf(stdout, "%d recipe(s) read from %s\n", len(projects), root)
	if len(unrecorded) > 0 {
		sort.Strings(unrecorded)
		fmt.Fprintf(stderr, "%d of %d recipe(s) record no provenance — each must say which of "+
			"the project's OWN files its build was written from, because that is the basis on "+
			"which it may exist at all (go-zpkg/packages#431):\n",
			len(unrecorded), len(projects))
		fmt.Fprintln(stderr, strings.Join(unrecorded, "\n"))
	}
	if len(fragments) > 0 {
		sort.Strings(fragments)
		fmt.Fprintf(stderr, "%d of %d recipe(s) cannot resolve alone — each needs another "+
			"recipe merged underneath it to say where its source comes from or how to build "+
			"it, and the only tree underneath ours is the upstream we may not copy "+
			"(go-zpkg/packages#431):\n",
			len(fragments), len(projects))
		fmt.Fprintln(stderr, strings.Join(fragments, "\n"))
	}
	if len(bad) > 0 {
		fmt.Fprintln(stderr, strings.Join(bad, "\n"))
		fmt.Fprintf(stderr, "%d recipe(s) cannot be read\n", len(bad))
		return 1
	}
	// Reported after the unreadable ones, and a failure in its own right: a
	// run that printed the list and exited 0 is a list nobody acts on.
	if len(unrecorded) > 0 || len(fragments) > 0 {
		return 1
	}
	return 0
}

// essentials are the keys a recipe must STATE to stand on its own: where its
// versions come from, where its content comes from, and how to turn that into a
// package. Miss any one and the recipe is an amendment to another recipe.
//
// `build` is in the list on purpose, though a fragment that lacked only `build`
// would be unusual: these are the three keys the factory reads to produce a
// bottle, and a list that held two of them would answer a narrower question
// than the one asked.
var essentials = []string{"versions", "distributable", "build"}

// missingEssentials names the essential keys a recipe document does not state,
// in the order of `essentials` rather than map order so two runs over one tree
// print the same line.
//
// `members` exempts a recipe entirely: a SET names a tree of packages by
// constraint and has no source and no build of its own, so judging it by
// `distributable` would report every set as a fragment.
func missingEssentials(doc map[string]any) []string {
	if _, ok := doc["members"]; ok {
		return nil
	}
	var miss []string
	for _, k := range essentials {
		if _, ok := doc[k]; !ok {
			miss = append(miss, k)
		}
	}
	return miss
}

// lintProjects lists the project directories under root, by the recipe file
// each one holds. A directory is a project because it has a recipe, not
// because of where it sits: the pantry nests them (x.org/protocol/xcb), so
// depth says nothing.
func lintProjects(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !recipefile.IsRecipe(d.Name()) {
			return nil
		}
		// Sliced rather than made relative: the path came from WalkDir(root),
		// so it is under root by construction and filepath.Rel could only fail
		// on inputs this cannot produce — an error arm no test could reach.
		// A recipe sitting directly in projects/ belongs to no project and is
		// left alone.
		dir := filepath.ToSlash(filepath.Dir(p))
		base := filepath.ToSlash(root)
		if dir == base {
			return nil
		}
		out = append(out, strings.TrimPrefix(dir, base+"/"))
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
