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
	if err := fset.Parse(args); err != nil {
		return 2
	}

	root := filepath.Join(*dir, "projects")
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

	var bad, unrecorded []string
	for _, proj := range projects {
		r, err := recipefile.Load(*dir, proj)
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
	if len(bad) > 0 {
		fmt.Fprintln(stderr, strings.Join(bad, "\n"))
		fmt.Fprintf(stderr, "%d recipe(s) cannot be read\n", len(bad))
		return 1
	}
	// Reported after the unreadable ones, and a failure in its own right: a
	// run that printed the list and exited 0 is a list nobody acts on.
	if len(unrecorded) > 0 {
		return 1
	}
	return 0
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
