package main

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

// cycles returns the strongly connected components of the walked graph that
// hold more than one project, plus any project that build-depends on itself.
//
// WHY the components and not the back edges. `visit` marks a project before
// recursing, so it terminates on a cycle by ignoring whichever edge closes it
// — and WHICH edge that is depends on the order projects were reached, not on
// the graph. A back edge is a property of the TRAVERSAL. A strongly connected
// component is a property of the graph, and two runs that reach it differently
// name the same set. Tarjan's 1972 algorithm ("Depth-first search and linear
// graph algorithms", SIAM J. Comput. 1(2)) finds them in one pass, and its
// low-link is the same depth-first walk this file already does.
//
// WHY it has to be said at all. Inside a component the emitted order is a
// guess, and a wrong guess is not visible in the output — it is a build that
// fails several steps later for a reason that looks local. Measured
// 2026-09-28: `bk closure --build` over the s390x seed put rust-lang.org AFTER
// rust-lang.org/cargo, which cannot build, and the seed's own order.txt has
// the opposite and was tuned by hand. Nothing in either output said the two
// disagreed about something arbitrary.
//
// This is the question Debian's bootstrap tooling asks first: botch (Johannes
// Schauer and Pietro Abate, "Bootstrapping Debian", and dose3's
// build-dependency analysis) computes the strongly connected components of the
// build graph and REPORTS them, because breaking one needs a staged build that
// only a person can decide on — a `<!stage1>` profile there, a pinned
// bootstrap bottle here. Naming them is the whole contribution; choosing for
// the user would be guessing with more confidence.
func (g *closureGraph) cycles() [][]string {
	// Tarjan, iterative in spirit but written recursively like the walk above:
	// the graphs here are the size of a pantry, and the walk that built them
	// recursed over the same edges.
	var (
		index    = map[string]int{}
		low      = map[string]int{}
		onStack  = map[string]bool{}
		stack    []string
		next     int
		out      [][]string
		strong   func(string)
		selfLoop = func(p string) bool { return slices.Contains(g.edges[p], p) }
	)
	strong = func(v string) {
		index[v], low[v] = next, next
		next++
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range g.edges[v] {
			if _, seen := index[w]; !seen {
				strong(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] != index[v] {
			return
		}
		var comp []string
		for {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			onStack[w] = false
			comp = append(comp, w)
			if w == v {
				break
			}
		}
		if len(comp) > 1 || selfLoop(v) {
			sort.Strings(comp)
			out = append(out, comp)
		}
	}
	// Sorted roots, so two runs over one graph produce one answer.
	roots := make([]string, 0, len(g.edges))
	for v := range g.edges {
		roots = append(roots, v)
	}
	sort.Strings(roots)
	for _, v := range roots {
		if _, ok := index[v]; !ok {
			strong(v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// printCycles writes one component per line, largest first.
func printCycles(comps [][]string, out io.Writer) {
	for _, c := range comps {
		fmt.Fprintln(out, strings.Join(c, " "))
	}
}

// warnCycles says on stderr that part of the order is arbitrary. It is not
// optional output: an order is a plan, and the reader has to know which of it
// was decided by the traversal.
func warnCycles(comps [][]string, warn func(string)) {
	if len(comps) == 0 || warn == nil {
		return
	}
	n := 0
	for _, c := range comps {
		n += len(c)
	}
	warn(fmt.Sprintf("closure: %d project(s) in %d dependency cycle(s) — the order WITHIN each is a guess, not a plan:", n, len(comps)))
	for _, c := range comps {
		warn("  " + strings.Join(c, " "))
	}
}
