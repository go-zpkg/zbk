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

	"github.com/go-zpkg/zpkb/vuln"
)

// advisoryFile is the name every project's advisory file has.
//
// Wolfi uses a FLAT directory of `<package>.advisories.yaml`, which works
// because an apk package name has no slashes. A pkgx project does
// ("x.org/protocol/xcb"), so the layout here mirrors the pantry's —
// `<dir>/<project>/advisories.yaml` — and the project name is the path.
const advisoryFile = "advisories.yaml"

// runAdvisories validates a tree of advisory files and says what state each
// project is in. It is what a CI lane runs over the advisory repository; the
// VEX document is emitted by whatever publishes an artifact, because only that
// knows the digest a statement must name.
func runAdvisories(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("advisories", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", "advisories", "the advisory tree to read")
	list := fset.Bool("list", false, "name every project and its current state")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	paths, err := advisoryPaths(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "advisories: %v\n", err)
		return 1
	}
	// An empty tree is a FAILURE, like `bk lint`'s: a validator that could not
	// find its corpus reports the same "no problems" as one that read it all.
	if len(paths) == 0 {
		fmt.Fprintf(stderr, "advisories: no %s under %s\n", advisoryFile, *dir)
		return 1
	}

	states := map[string]int{}
	var bad, lines []string
	total := 0
	for _, rel := range paths {
		b, err := os.ReadFile(filepath.Join(*dir, filepath.FromSlash(rel), advisoryFile))
		if err != nil {
			bad = append(bad, fmt.Sprintf("  %s: %v", rel, err))
			continue
		}
		f, err := vuln.ParseAdvisories(b)
		if err != nil {
			bad = append(bad, fmt.Sprintf("  %s: %v", rel, err))
			continue
		}
		// ⛔ THE PATH AND THE FILE MUST AGREE. A file copied from a
		// neighbouring project and edited in part would otherwise attach its
		// findings to the wrong package — and every consumer downstream would
		// believe it, because nothing else in the record says which project it
		// is about.
		if f.Project != rel {
			bad = append(bad, fmt.Sprintf("  %s: the file says project %q", rel, f.Project))
			continue
		}
		for _, a := range f.Advisories {
			total++
			states[a.Latest().Type]++
		}
		if *list {
			lines = append(lines, fmt.Sprintf("  %-40s %d advisory(ies), %s", rel, len(f.Advisories), summarise(f)))
		}
	}

	fmt.Fprintf(stdout, "%d project(s) read from %s, %d advisory(ies)\n", len(paths)-len(bad), *dir, total)
	// Every state named, zero included, so a run that read nothing cannot be
	// mistaken for one that found nothing.
	for _, t := range []string{
		vuln.EventDetection, vuln.EventTruePositive, vuln.EventFalsePositive,
		vuln.EventFixed, vuln.EventFixNotPlanned, vuln.EventPendingUpstreamFix,
	} {
		fmt.Fprintf(stdout, "  %-28s %d\n", t, states[t])
	}
	for _, l := range lines {
		fmt.Fprintln(stdout, l)
	}
	if len(bad) > 0 {
		fmt.Fprintf(stderr, "%d file(s) cannot be used:\n%s\n", len(bad), strings.Join(bad, "\n"))
		return 1
	}
	return 0
}

// summarise names the states present in one project, with counts, ordered so
// two runs agree.
func summarise(f *vuln.AdvisoryFile) string {
	n := map[string]int{}
	for _, a := range f.Advisories {
		n[a.Latest().Type]++
	}
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, n[k]))
	}
	return strings.Join(parts, ", ")
}

// advisoryPaths lists the projects under root, by the advisory file each one
// holds — the same rule lintProjects uses: a directory is a project because it
// has the file, not because of where it sits.
func advisoryPaths(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() != advisoryFile {
			return nil
		}
		dir := filepath.ToSlash(filepath.Dir(p))
		base := filepath.ToSlash(root)
		if dir == base {
			// A file at the root belongs to no project, and reading it would
			// name the root as one.
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
