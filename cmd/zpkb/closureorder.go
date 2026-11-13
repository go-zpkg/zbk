package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// checkOrder reads a build order somebody wrote and says what it decided.
//
// An order over a graph with cycles is not a topological sort — there is none
// — it is a topological sort of everything else PLUS a choice of which edges
// to give up on. Debian's bootstrap tooling calls that choice a FEEDBACK ARC
// SET, and botch computes one (along with feedback vertex sets, strong
// articulation points and bridges) precisely because it is the thing a person
// has to decide: the Debian build graph in native compilation has a single
// strongly connected component of about a thousand vertices, and no ordering
// of it exists until some build dependencies are dropped and staged.
//
// Ours is smaller and the same shape: 27 of the s390x seed's 77 projects are
// in one component. The seed's order.txt was tuned by hand, and the choice it
// embodies was written nowhere — so nothing could say whether an edit to it
// had broken something that was not a cycle at all.
//
// Two answers, and they are different in kind:
//
//	an edge BETWEEN components, out of order   a MISTAKE. There is no reason
//	                                           for it; a topological sort of
//	                                           the condensation exists.
//	an edge WITHIN one component, out of order  the CHOICE. Unavoidable, and
//	                                           worth reading, because it is
//	                                           what the first pass has to do
//	                                           without.
//
// It does not propose an order. Choosing a minimum feedback arc set is
// NP-hard, and which edge is cheapest to give up is a fact about the software,
// not about the graph: whether gnu.org/gcc can be built by the host's gcc is
// not something a walk can know.
func checkOrder(g *closureGraph, path string, stdout, stderr io.Writer) int {
	order, err := readOrder(path)
	if err != nil {
		fmt.Fprintln(stderr, "closure:", err)
		return 2
	}
	at := make(map[string]int, len(order))
	for i, p := range order {
		at[p] = i
	}

	// Which component each project belongs to. A project in none is its own.
	comp := map[string]int{}
	comps := g.cycles()
	for i, c := range comps {
		for _, p := range c {
			comp[p] = i + 1
		}
	}

	var missing, mistakes, choices []string
	for _, u := range g.order {
		iu, ok := at[u]
		if !ok {
			missing = append(missing, u)
			continue
		}
		for _, v := range g.edges[u] {
			iv, ok := at[v]
			if !ok {
				continue // named by the graph, not in the order: reported once, above
			}
			if iv < iu {
				continue // built before its dependent, as it must be
			}
			line := fmt.Sprintf("  %s is built at %d and needs %s at %d", u, iu+1, v, iv+1)
			if comp[u] != 0 && comp[u] == comp[v] {
				choices = append(choices, line)
				continue
			}
			mistakes = append(mistakes, line)
		}
	}

	sort.Strings(missing)
	sort.Strings(mistakes)
	sort.Strings(choices)
	fmt.Fprintf(stdout, "%d project(s) in the order, %d in the closure, %d cycle(s)\n",
		len(order), len(g.order), len(comps))
	if len(choices) > 0 {
		fmt.Fprintf(stdout, "%d edge(s) this order gives up on, all INSIDE a cycle — the feedback arc set it chose:\n", len(choices))
		for _, c := range choices {
			fmt.Fprintln(stdout, c)
		}
	}
	code := 0
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "%d project(s) the closure needs and the order does not name:\n  %s\n",
			len(missing), strings.Join(missing, " "))
		code = 1
	}
	if len(mistakes) > 0 {
		fmt.Fprintf(stderr, "%d edge(s) out of order OUTSIDE any cycle — nothing forces these:\n", len(mistakes))
		for _, m := range mistakes {
			fmt.Fprintln(stderr, m)
		}
		code = 1
	}
	return code
}

// readOrder reads one project per line, ignoring blanks and # comments, and
// the `project@constraint` form a dispatch uses.
func readOrder(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// `tcl-lang.org@=9.0.4` names tcl-lang.org.
		if i := strings.Index(line, "@"); i > 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no project — an empty order agrees with everything", path)
	}
	return out, nil
}
