package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/zbk/logical"
	"github.com/go-zpkg/zbk/target"
)

// runAffected answers "a vulnerability was found in these projects — what has
// to be rebuilt?", which is the REVERSE of every other walk in this program.
//
// # Why it exists
//
// `closure` walks forward: what does this need. The question a security fix
// asks is the other one — what needs THIS — and nothing here could answer it.
// go-zpkg/zbk#155 is the shape: "#154 will change ncurses' layout on its next
// rebuild, and 49 recipes include <curses.h>", a number somebody counted by
// hand. go-zpkg/packages#447 is the same question for a CVE.
//
// ⛔⛔ THE WALK STARTS FROM THE WHOLE PANTRY, NOT FROM THE NAMED PROJECTS, and
// that is the one thing a naive implementation gets wrong in a way nothing
// notices. The reverse closure of X is only complete if the graph contains
// EVERY project that could depend on X; a walk seeded with X reaches what X
// needs and learns nothing about who needs X. The cost is reading every recipe,
// which is the price of an answer rather than a sample.
//
// # What it refuses
//
// A rebuild set computed from a graph with holes in it. `missing` is a project
// named as a dependency whose recipe this pantry does not hold — and a node
// whose DEPENDENCIES cannot be read may itself depend on an affected project,
// which would make it affected, which would make ITS dependents affected too.
// So an incomplete graph yields a LOWER BOUND, and a lower bound presented as
// an answer is how a rebuild misses the package that mattered.
//
// `--allow-missing` proceeds and PRINTS them, because an exemption nobody can
// see is how the next person trusts the number.
func runAffected(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("affected", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pantryDir := fs.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout dir")
	overridesDir := fs.String("overrides", envOr("OVERRIDES", ""), "directory of *.hcl logical recipe overrides, applied to the pantry's recipes as they are read")
	overlayDir := fs.String("overlay", envOr("PANTRY_OVERLAY_DIR", ""), "an overlay checkout consulted BEFORE the pantry, as the factory consults ZPKG_PANTRY_OVERLAY")
	platform := fs.String("platform", envOr("PLATFORM", "linux/x86-64"), "target os/arch")
	withBuild := fs.Bool("build", false, "follow BUILD dependencies as well as runtime ones: a project that only BUILDS against an affected one still has to be rebuilt when the fix changes headers or a static library")
	allowMissing := fs.Bool("allow-missing", false, "answer although the graph has holes; every missing project is PRINTED, because the answer is then a lower bound")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	named := fs.Args()
	if len(named) == 0 {
		fmt.Fprintln(stderr, "affected: name at least one project — the rebuild set is the reverse closure of something")
		return 2
	}

	lset, err := logical.LoadDir(*overridesDir)
	if err != nil {
		fmt.Fprintln(stderr, "affected:", err)
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	tgt := target.Target{Platform: osn, Arch: arch}

	// ⛔ everyProject RETURNS NO ERROR, and the first version of this had an
	// error arm for it that nothing could reach: a directory it cannot read is
	// simply a directory with no recipes, and the one case that matters —
	// NOTHING found anywhere — is checked below on its own. A dead error path
	// is worse than none: it reads as handled.
	every := everyProject(*pantryDir, *overlayDir)
	if len(every) == 0 {
		// ⛔ A pantry that could not be read yields an empty graph, whose
		// reverse closure is "nothing to rebuild" — the most dangerous answer
		// this command can give.
		fmt.Fprintf(stderr, "affected: no recipe found under %s: a reverse closure over an empty graph would report that nothing needs rebuilding\n", *pantryDir)
		return 2
	}

	g := newClosureGraph(lset, *pantryDir, tgt, *withBuild, func(string) {})
	g.overlay = *overlayDir
	for _, p := range every {
		g.visit(p)
	}

	// A project nobody can find is not a project with no dependents.
	var unknown []string
	for _, n := range named {
		if !g.seen[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		fmt.Fprintf(stderr, "affected: %d named project(s) are not in this pantry, so their dependents cannot be computed: %s\n",
			len(unknown), strings.Join(unknown, " "))
		return 2
	}

	if len(g.missing) > 0 {
		miss := dedupe(g.missing)
		if !*allowMissing {
			fmt.Fprintf(stderr, "affected: %d project(s) are named as a dependency and have no recipe here, so this graph has holes:\n  %s\n",
				len(miss), strings.Join(miss, " "))
			fmt.Fprintln(stderr, "  Each could itself depend on one of the named projects, which would make it AND its dependents part of the set.")
			fmt.Fprintln(stderr, "  The answer would be a lower bound. Pass --allow-missing to get it anyway; they are printed when you do.")
			return 2
		}
		fmt.Fprintf(stdout, "⚠ LOWER BOUND: %d project(s) could not be read, so anything that depends on one of them may be missing from this set:\n  %s\n\n",
			len(miss), strings.Join(miss, " "))
	}

	set := reverseClosure(g.edges, named)

	// Emitted in the graph's own build order — dependencies before dependents —
	// so the list can be handed to a factory rather than re-sorted by hand.
	var out []string
	for _, p := range g.order {
		if set[p] {
			out = append(out, p)
		}
	}
	fmt.Fprintf(stdout, "%d project(s) to rebuild, dependencies first:\n", len(out))
	for _, p := range out {
		mark := "  "
		if contains(named, p) {
			mark = "* " // the project the advisory names, not a dependent
		}
		fmt.Fprintln(stdout, mark+p)
	}
	return 0
}

// reverseClosure returns every project that reaches one of `named` by following
// dependency edges — the set that has to be rebuilt.
//
// `edges` is project -> its dependencies, so this inverts it first. Inverting
// rather than walking forward from each candidate is what keeps this linear in
// the graph instead of quadratic in the pantry.
func reverseClosure(edges map[string][]string, named []string) map[string]bool {
	rev := map[string][]string{}
	for from, tos := range edges {
		for _, to := range tos {
			rev[to] = append(rev[to], from)
		}
	}
	set := map[string]bool{}
	var queue []string
	for _, n := range named {
		if !set[n] {
			set[n] = true
			queue = append(queue, n)
		}
	}
	// ⛔ The named projects are IN the set: they are the ones that have to be
	// rebuilt first, and a list of only their dependents would be a plan that
	// rebuilds against the unfixed thing.
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, up := range rev[cur] {
			if !set[up] {
				set[up] = true
				queue = append(queue, up)
			}
		}
	}
	return set
}

// everyProject names each project the pantry or the overlay holds a recipe for.
//
// A root it cannot read contributes nothing, which is why this returns no
// error: "that directory has no recipes" and "that directory is not there" lead
// to the same list, and the case that must not pass silently — nothing found in
// EITHER — is the caller's own check.
func everyProject(pantry, overlay string) []string {
	seen := map[string]bool{}
	var out []string
	for _, root := range []string{overlay, pantry} {
		if root == "" {
			continue
		}
		// ⛔⛔ `<root>/projects/<project>/package.hcl` AND NOTHING ELSE, because
		// that is the layout the GRAPH LOADER reads. A first draft fell back to
		// reading recipes at the root when `projects/` held none — and the
		// result was worse than not supporting it: enumeration found the
		// projects, `load` could not open any of them, and every one came back
		// as a HOLE. The command then refused with "2 projects are named as a
		// dependency and have no recipe here" for a pantry that simply was not
		// one. Enumeration and loading have to agree about the layout, and the
		// loader is the one that decides.
		ps, _ := lintProjects(filepath.Join(root, "projects"))
		for _, p := range ps {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
