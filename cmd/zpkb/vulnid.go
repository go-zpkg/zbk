package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/vuln"
)

// runVulnID reports, for every recipe in a pantry, the name a vulnerability
// database will recognise the project under — and, more usefully, how many
// projects have no such name at all.
//
// It makes NO network call. The alternative, one query per project, is 1908
// requests against a budget this fleet shares with Renovate; and the answer to
// "can this be asked at all?" is in the recipes.
//
// This replaces a throwaway census script. The three mistakes that script made
// are the three things tested here: a corpus it could not read reported zero, a
// map iteration made the totals differ between runs, and a project in two
// ecosystems was assigned to whichever the loop reached first.
func runVulnID(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("vulnid", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", ".", "the pantry checkout to read")
	table := fset.String("table", "", "an identity table declaring what the recipes do not say")
	list := fset.String("list", "", "also list every project with this source: declared, derived or none")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	var tab *vuln.Table
	if *table != "" {
		b, err := os.ReadFile(*table)
		if err != nil {
			fmt.Fprintf(stderr, "vulnid: %v\n", err)
			return 1
		}
		if tab, err = vuln.ParseTable(b); err != nil {
			fmt.Fprintf(stderr, "vulnid: %v\n", err)
			return 1
		}
	}

	wanted, ok := sourceNamed(*list)
	if !ok {
		fmt.Fprintf(stderr, "vulnid: -list %q: want declared, derived or none\n", *list)
		return 2
	}

	root := filepath.Join(*dir, "projects")
	projects, err := lintProjects(root)
	if err != nil {
		fmt.Fprintf(stderr, "vulnid: %v\n", err)
		return 1
	}
	// An empty corpus is a FAILURE. A census that could not find its recipes
	// prints the same "0 with no identity" as one that read them all and found
	// none, and this fleet has already published a zero that meant "could not
	// read".
	if len(projects) == 0 {
		fmt.Fprintf(stderr, "vulnid: no recipe under %s — the layout changed\n", root)
		return 1
	}

	counts := map[string]int{}
	dbs := map[string]int{}
	var unreadable []string
	var listed []string
	for _, proj := range projects {
		r, err := recipefile.Load(*dir, proj)
		if err != nil {
			unreadable = append(unreadable, proj)
			continue
		}
		ids, src := tab.For(proj, r.Versions)
		counts[src.String()]++
		for _, id := range ids {
			dbs[id.DB]++
		}
		if *list != "" && src == wanted {
			listed = append(listed, fmt.Sprintf("  %-44s %s", proj, join(ids)))
		}
	}

	fmt.Fprintf(stdout, "%d recipe(s) read from %s\n", len(projects), root)
	// The totals ALWAYS, and named, so a run that read nothing cannot be
	// mistaken for one that found nothing.
	for _, s := range []string{"declared", "derived", "none"} {
		fmt.Fprintf(stdout, "  %-9s %d\n", s, counts[s])
	}
	if len(dbs) > 0 {
		fmt.Fprintln(stdout, "by database:")
		for _, db := range sortedCountKeys(dbs) {
			fmt.Fprintf(stdout, "  %-14s %d\n", db, dbs[db])
		}
	}
	if len(listed) > 0 {
		fmt.Fprintf(stdout, "%s (%d):\n", *list, len(listed))
		for _, l := range listed {
			fmt.Fprintln(stdout, l)
		}
	}
	// A recipe that cannot be read has no identity either, and saying so is
	// the difference between a measurement and a guess.
	if len(unreadable) > 0 {
		fmt.Fprintf(stderr, "%d recipe(s) cannot be read, so nothing is claimed about them:\n", len(unreadable))
		for _, p := range unreadable {
			fmt.Fprintln(stderr, " ", p)
		}
		return 1
	}
	return 0
}

// sourceNamed maps the -list value onto a source. The empty string lists
// nothing, which is not an error.
func sourceNamed(s string) (vuln.Source, bool) {
	switch s {
	case "":
		return vuln.SourceNone, true
	case "declared":
		return vuln.SourceDeclared, true
	case "derived":
		return vuln.SourceDerived, true
	case "none":
		return vuln.SourceNone, true
	}
	return vuln.SourceNone, false
}

func join(ids []vuln.Identity) string {
	if len(ids) == 0 {
		return "-"
	}
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += " "
		}
		out += id.DB + ":" + id.Name
	}
	return out
}

// sortedCountKeys orders by count descending, then by name, so the shape of
// the fleet is readable and two runs agree.
func sortedCountKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
