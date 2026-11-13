package main

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// closureGraph walks a project set following runtime dependencies and,
// optionally, build dependencies too.
//
// The two are different graphs and it matters which one a question is about.
// The runtime closure is what a CONSUMER needs and it is a DAG, so the factory
// can build it deps-first. Adding build dependencies makes it a graph with
// cycles — gnu.org/gcc build-depends on gnu.org/gcc, curl.se/ca-certs runs
// curl to fetch its bundle while curl needs the bundle — and on an
// architecture with no bottles at all that is the difference between a plan
// and a wish.
//
// Every reduction goes through build.ReduceDeps, the same one the builder
// uses. A separate reading of the same YAML is a proxy, and the proxy this
// replaces was wrong three times: it missed `>=5<8.13` because its operator
// list had no ">", missed a constraint with a trailing `#` comment, and could
// not see the soname channel at all.
type closureGraph struct {
	order   []string // post-order: dependencies before dependents
	missing []string // named as a dependency, no recipe in this pantry
	// edges is the graph as WALKED, project to project, so the cycles it had
	// to break can be named afterwards. The walk itself cannot say: it
	// terminates by ignoring whichever edge closes a cycle, and which one that
	// is depends on the order projects were reached. See cycles().
	edges   map[string][]string
	demands map[string]map[string][]string
	seen    map[string]bool
	pantry  string
	overlay string
	// set is the logical overrides, applied to a PANTRY recipe as it is read.
	//
	// It is here for the reason go-zpkg/bk#224 exists: bk has two closure
	// walks, and teaching one of them something the other does not know makes
	// `bk closure` describe a build the factory would not perform. That defect
	// was fixed hours before this field was added, and its first draft
	// reproduced it — `bk closure --build` quietly ignored every override.
	set      *logical.Set
	tgt      target.Target
	withBuil bool
	warn     func(string)
}

func newClosureGraph(set *logical.Set, pantryDir string, tgt target.Target, withBuild bool, warn func(string)) *closureGraph {
	return &closureGraph{
		demands: map[string]map[string][]string{},
		seen:    map[string]bool{},
		edges:   map[string][]string{},
		pantry:  pantryDir, tgt: tgt, withBuil: withBuild, warn: warn, set: set,
	}
}

// visit marks before recursing, which breaks cycles rather than hiding them:
// with --build the graph HAS cycles, and a walk that refused to terminate on
// one would be answering a question nobody asked.
func (g *closureGraph) visit(proj string) {
	if g.seen[proj] {
		return
	}
	g.seen[proj] = true
	rec, err := g.load(proj)
	if err != nil {
		g.missing = append(g.missing, proj)
		if g.warn != nil {
			g.warn(fmt.Sprintf("closure: skip %s: %v", proj, err))
		}
		return
	}
	g.record(proj, rec.Dependencies)
	g.link(proj, rec.Dependencies)
	for _, spec := range build.DepSpecs(rec.Dependencies, g.tgt) {
		g.visit(build.SpecProject(spec))
	}
	if g.withBuil {
		bd := build.BuildDeps(rec)
		g.record(proj, bd)
		g.link(proj, bd)
		for _, spec := range build.DepSpecs(bd, g.tgt) {
			g.visit(build.SpecProject(spec))
		}
	}
	g.order = append(g.order, proj)
}

// record notes who asked for what. A constraint is kept only when it says
// something: "*" and "" are every version, and listing them would bury the
// handful that pin a LINE under a hundred that do not.
// link records the edges of the graph as walked. It is separate from record
// because record drops "*" and "" — a constraint that says nothing is still a
// dependency, and a cycle closed by one is still a cycle.
func (g *closureGraph) link(by string, deps map[string]any) {
	for _, spec := range build.DepSpecs(deps, g.tgt) {
		to := build.SpecProject(spec)
		if !slices.Contains(g.edges[by], to) {
			g.edges[by] = append(g.edges[by], to)
		}
	}
	sort.Strings(g.edges[by])
}

func (g *closureGraph) record(by string, deps map[string]any) {
	for dep, cons := range build.ReduceDeps(deps, g.tgt) {
		if cons == "" || cons == "*" {
			continue
		}
		if g.demands[dep] == nil {
			g.demands[dep] = map[string][]string{}
		}
		// A project can ask for the same thing twice — rust-lang.org/cargo
		// names openssl.org in BOTH its runtime and its build dependencies —
		// and "asked by cargo, cargo" reads as two demands where there is one.
		if !slices.Contains(g.demands[dep][cons], by) {
			g.demands[dep][cons] = append(g.demands[dep][cons], by)
		}
	}
}

// constrained lists, in the graph's own order, every project some dependent
// pins to a version line, with who asks for what.
//
// This is what `max_versions=1` cannot know. It builds the NEWEST, and
// openssl.org 4.0.2 does not satisfy curl.se's "^3" — one dispatch, one
// discovery, on a two-core machine.
func (g *closureGraph) constrained() []string {
	var out []string
	for _, proj := range g.order {
		d := g.demands[proj]
		if len(d) == 0 {
			continue
		}
		out = append(out, proj)
		cs := make([]string, 0, len(d))
		for c := range d {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		for _, c := range cs {
			by := append([]string(nil), d[c]...)
			sort.Strings(by)
			out = append(out, fmt.Sprintf("    %-14s asked by %s", c, strings.Join(by, ", ")))
		}
	}
	return out
}

// implicitExtras are the soname providers this walk could not have reached.
//
// A dependency the maps supply exists only in the compiled artefact — perl
// declares nothing about libcrypt — so a walk over RECIPES is blind to it by
// construction, and a plan built from one discovers them a failed build at a
// time. The set is bounded, so naming it turns a surprise into a list.
//
// Reported separately from the order, and never mixed into it: these are
// projects that MAY be pulled in, not ones this closure is known to need.
func (g *closureGraph) implicitExtras() []string {
	var out []string
	for _, p := range bottle.SonameProviders() {
		if !g.seen[p] {
			out = append(out, p)
		}
	}
	return out
}

// printGraph writes whichever view the flags asked for.
func printGraph(g *closureGraph, constraints, pins, implicit bool, stdout io.Writer) {
	if pins {
		ps, conflicts := g.pins()
		for _, p := range ps {
			fmt.Fprintln(stdout, p)
		}
		// Named, not dropped: a project whose dependents disagree needs one
		// build per line, and a list that silently omitted it would read as
		// "nothing to do here".
		for _, c := range conflicts {
			fmt.Fprintf(stdout, "# NO single version: %s\n", c)
		}
		return
	}
	if constraints {
		for _, l := range g.constrained() {
			fmt.Fprintln(stdout, l)
		}
		return
	}
	for _, p := range g.order {
		fmt.Fprintln(stdout, p)
	}
	if implicit {
		for _, p := range g.implicitExtras() {
			fmt.Fprintf(stdout, "%s\t# soname provider — no recipe declares it\n", p)
		}
	}
}

// load reads a recipe the way this walk must: the overlay first, as a consumer
// resolves, and the pantry's own copy with the logical overrides applied, as
// the factory builds.
func (g *closureGraph) load(proj string) (*pantry.Recipe, error) {
	if g.overlay != "" {
		// MERGED over upstream, not preferred whole. An overlay entry states
		// only the keys it changes now, so reading one on its own is a
		// fragment: `bk closure --build curl.se` went from 54 projects to 8
		// the first time this walk met a reduced entry, because it saw
		// `dependencies` and never upstream's build dependencies.
		return recipefile.LoadMerged(g.set, g.overlay, g.pantry, proj)
	}
	return recipefile.LoadOverridden(g.set, g.pantry, proj)
}
