package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/vuln"
	"gopkg.in/yaml.v3"
)

// runVulnFetch asks OSV what it knows about a pantry, and (only with -write)
// records what comes back as `detection` events.
//
// It REPORTS by default. A sweep that writes on its first run writes whatever
// its first run happened to find, into files a person then has to audit; and
// the thing worth knowing before writing anything is the scale — whether 129
// queryable projects yield ten findings or four hundred.
//
// This is the only command in bk that talks to a vulnerability database, and
// it is one HTTP request per thousand identities. Nothing here touches the
// GitHub API, so nothing here competes with Renovate.
func runVulnFetch(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("vulnfetch", flag.ContinueOnError)
	fset.SetOutput(stderr)
	dir := fset.String("dir", ".", "the pantry checkout to read")
	table := fset.String("table", "", "an identity table declaring what the recipes do not say")
	out := fset.String("advisories", "advisories", "the advisory tree to record detections in")
	write := fset.Bool("write", false, "write detections into the advisory tree instead of only reporting")
	endpoint := fset.String("endpoint", "", "OSV batch query endpoint (default "+vuln.OSVEndpoint+")")
	only := fset.String("project", "", "ask about this project alone")
	catalog := fset.String("catalog", "",
		"a published catalogue; ask OSV about the version it says we publish, not about the package as a whole")
	failOnNew := fset.Bool("fail-on-new", false,
		"exit non-zero when a finding has no decision recorded in the advisory tree")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	tab, code := loadIdentityTable(*table, stderr)
	if code != 0 {
		return code
	}

	ids, byIdentity, code := pantryIdentities(*dir, *only, tab, stdout, stderr)
	if code != 0 {
		return code
	}

	pinned, atVersion, unpublished, code := pinIdentities(*catalog, ids, byIdentity, stderr)
	if code != 0 {
		return code
	}

	client := &vuln.OSVClient{Endpoint: *endpoint}
	found, skipped, err := client.AskPinned(pinned)
	if err != nil {
		fmt.Fprintf(stderr, "vulnfetch: %v\n", err)
		return 1
	}

	// ⛔ SAY WHICH QUESTION WAS ASKED. Without a catalogue this reports every
	// advisory a package has ever carried, most of them fixed long before the
	// version we ship — 748 findings across 21 projects over the pkgxdev
	// pantry on 2026-10-17, and a list that large with no decision behind any
	// line is read once and never again. The number means something different
	// in each mode and the output must not let them be confused.
	switch {
	case atVersion > 0:
		fmt.Fprintf(stdout, "%d of them asked AT the version the catalogue publishes; the rest as a whole package\n", atVersion)
	case *catalog != "":
		// ⛔ NOT the "pass -catalog" line: they did. A catalogue that names no
		// version for anything asked is a different situation from no
		// catalogue at all, and advice the reader has already followed reads
		// as the tool not having noticed. Found by a test whose pantry
		// published two versions behind one identity, so nothing could be
		// pinned and the suggestion came back anyway.
		fmt.Fprintf(stdout, "asked about each package AS A WHOLE — %s names no single published version for any identity asked\n", *catalog)
	default:
		fmt.Fprintln(stdout, "asked about each package AS A WHOLE — pass -catalog to ask only about the versions we publish")
	}
	// ⛔ OUTSIDE THE SWITCH, so the loudest case is not also the quietest.
	//
	// A project the catalogue gives no version for is not published on this
	// platform, and a vulnerability in it is not a finding about us — the
	// first run with -catalog reported "90 finding(s) across 5 project(s)"
	// and every one of the five answered `no bottle here`. Right figures,
	// different meaning.
	//
	// But narrowing a scan is only honest if the count says by how much.
	// Written inside the `atVersion > 0` arm, as it was first, this line
	// vanished exactly when EVERYTHING was skipped — the case a reader most
	// needs told, and the one a test caught.
	if unpublished > 0 {
		fmt.Fprintf(stdout, "%d identity(ies) NOT asked: %s publishes no version of them for this platform\n", unpublished, *catalog)
	}

	// ⛔ WHAT WAS NOT ASKED, FIRST. OSV cannot answer about a repository, and
	// an unasked question looks exactly like a clean answer. Measured: 1186 of
	// this pantry's identities are repository-keyed, so a sweep that stayed
	// quiet about them would report "no known vulnerabilities" for three
	// quarters of the fleet.
	// ⛔ COUNTED AGAINST `pinned`, NOT `ids`. Once an identity can be dropped
	// before AskPinned sees it, `skipped` comes from a SMALLER population
	// than `ids`, and len(ids)-len(skipped) overstates: the first run of the
	// skip printed "589 identity(ies) asked" where 137 were. Same arithmetic
	// mistake as the "1217 of 171" one below, in the other direction.
	fmt.Fprintf(stdout, "%d identity(ies) asked, %d not answerable by OSV (repository- or CPE-keyed)\n",
		len(pinned)-len(skipped), len(skipped))

	perProject := map[string][]vuln.Finding{}
	for _, f := range found {
		for _, project := range byIdentity[f.Identity] {
			perProject[project] = append(perProject[project], f)
		}
	}
	fmt.Fprintf(stdout, "%d finding(s) across %d project(s)\n", len(found), len(perProject))
	for _, project := range sortedProjects(perProject) {
		fmt.Fprintf(stdout, "  %s\n", project)
		for _, f := range perProject[project] {
			fmt.Fprintf(stdout, "    %-24s %s:%s\n", f.ID, f.Identity.DB, f.Identity.Name)
		}
	}
	// The merge runs in BOTH modes, writing only under -write. Counting what
	// is new is the same work as recording it, and doing it only on the write
	// path is what made this command a report with no verdict: 90 findings
	// printed, every one of them already triaged or not, and no way to tell
	// which without reading the tree by hand.
	unrecorded, code := recordDetections(*out, perProject, !*write, stdout, stderr)
	if code != 0 {
		return code
	}
	if !*write && len(found) > 0 {
		fmt.Fprintf(stdout, "nothing written — %d of these are not yet recorded; pass -write to record them as detections\n", unrecorded)
	}
	// ⛔ THE GATE IS ON WHAT IS NEW, NOT ON WHAT EXISTS. A job that failed
	// while any finding existed would be red from its first run — 90 of them
	// on 2026-10-17 — and a check that is red every day is one people learn
	// to scroll past. That is not hypothetical here: versioncheck on the
	// landing site was red for eight days running for exactly that reason.
	//
	// Red on something NEW is a question with an answer: rebuild, or record
	// why the bottle is not affected. Both make it green again.
	if *failOnNew && unrecorded > 0 {
		fmt.Fprintf(stderr, "vulnfetch: %d finding(s) with no decision in %s — rebuild, or record why the published version is not affected\n",
			unrecorded, *out)
		return 1
	}
	return 0
}

// loadIdentityTable reads the optional table, or returns the exit code.
func loadIdentityTable(path string, stderr io.Writer) (*vuln.Table, int) {
	if path == "" {
		return nil, 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "vulnfetch: %v\n", err)
		return nil, 1
	}
	tab, err := vuln.ParseTable(b)
	if err != nil {
		fmt.Fprintf(stderr, "vulnfetch: %v\n", err)
		return nil, 1
	}
	return tab, 0
}

// pantryIdentities collects every identity in a pantry, and the projects each
// one belongs to.
//
// An identity can belong to SEVERAL projects — two recipes naming the same
// upstream repository — so the reverse map is one-to-many. Keeping it
// one-to-one would attribute a finding to whichever project was read last.
func pantryIdentities(dir, only string, tab *vuln.Table, stdout, stderr io.Writer) ([]vuln.Identity, map[vuln.Identity][]string, int) {
	root := filepath.Join(dir, "projects")
	projects, err := lintProjects(root)
	if err != nil {
		fmt.Fprintf(stderr, "vulnfetch: %v\n", err)
		return nil, nil, 1
	}
	if len(projects) == 0 {
		fmt.Fprintf(stderr, "vulnfetch: no recipe under %s — the layout changed\n", root)
		return nil, nil, 1
	}
	byIdentity := map[vuln.Identity][]string{}
	var ids []vuln.Identity
	seen := map[vuln.Identity]bool{}
	read := 0
	for _, project := range projects {
		if only != "" && project != only {
			continue
		}
		r, err := recipefile.Load(dir, project)
		if err != nil {
			// Named, not counted as having no vulnerabilities.
			fmt.Fprintf(stderr, "vulnfetch: %s: %v\n", project, err)
			continue
		}
		read++
		got, _ := tab.For(project, r.Versions)
		for _, id := range got {
			byIdentity[id] = append(byIdentity[id], project)
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if read == 0 {
		fmt.Fprintf(stderr, "vulnfetch: no recipe read — %q matched nothing\n", only)
		return nil, nil, 1
	}
	fmt.Fprintf(stdout, "%d recipe(s) read from %s\n", read, root)
	return ids, byIdentity, 0
}

// recordDetections merges the findings into each project's advisory file.
// recordDetections merges every finding into the advisory tree and returns how
// many were NOT already there.
//
// With dry set it does the same merge in memory and writes nothing — the count
// is the point, and computing it any other way would be a second definition of
// "already recorded" that could disagree with the one that writes.
func recordDetections(out string, perProject map[string][]vuln.Finding, dry bool, stdout, stderr io.Writer) (int, int) {
	now := time.Now().UTC().Truncate(time.Second)
	added, touched := 0, 0
	for _, project := range sortedProjects(perProject) {
		path := filepath.Join(out, filepath.FromSlash(project), advisoryFile)
		f, err := loadOrCreate(path, project)
		if err != nil {
			fmt.Fprintf(stderr, "vulnfetch: %s: %v\n", project, err)
			return 0, 1
		}
		n := vuln.MergeDetections(f, perProject[project], now)
		if n == 0 {
			continue
		}
		added += n
		touched++
		if dry {
			continue
		}
		// An AdvisoryFile holds strings, ints and time.Time, all of which
		// yaml.Marshal encodes — there is no error arm here rather than an
		// unreachable one no test could enter.
		b, _ := yaml.Marshal(f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(stderr, "vulnfetch: %v\n", err)
			return 0, 1
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			fmt.Fprintf(stderr, "vulnfetch: %v\n", err)
			return 0, 1
		}
	}
	if !dry {
		fmt.Fprintf(stdout, "%d detection(s) written across %d file(s)\n", added, touched)
	}
	return added, 0
}

// loadOrCreate reads a project's advisory file, or returns an empty one.
//
// An existing file is PARSED, not appended to blindly: a file that does not
// parse must stop the sweep rather than be replaced by one holding only
// today's detections, which would delete every decision recorded in it.
func loadOrCreate(path, project string) (*vuln.AdvisoryFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &vuln.AdvisoryFile{SchemaVersion: vuln.AdvisoryVersion, Project: project}, nil
		}
		return nil, err
	}
	f, err := vuln.ParseAdvisories(b)
	if err != nil {
		return nil, err
	}
	if f.Project != project {
		return nil, fmt.Errorf("%s says project %q", path, f.Project)
	}
	return f, nil
}

func sortedProjects(m map[string][]vuln.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pinIdentities attaches the version the CATALOGUE says we publish to each
// identity, so OSV is asked about what we ship rather than about the package
// in the abstract.
//
// Without -catalog every identity is asked as a whole package, which is what
// this command did before and is still the right question when nothing has
// been published yet.
//
// ⛔ AN IDENTITY SHARED BY PROJECTS AT DIFFERENT VERSIONS IS ASKED WITHOUT ONE.
// Two projects can carry the same upstream identity, and if they publish
// different versions there is no single version to ask about. Picking either
// would under-report for the other, and under-reporting is the direction that
// hides a vulnerability — so the question widens back to the whole package and
// the count says so.
func pinIdentities(path string, ids []vuln.Identity, byIdentity map[vuln.Identity][]string, stderr io.Writer) (pinned []vuln.Pinned, atVersion, unpublished, code int) {
	out := make([]vuln.Pinned, 0, len(ids))
	if path == "" {
		for _, id := range ids {
			out = append(out, vuln.Pinned{Identity: id})
		}
		return out, 0, 0, 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "vulnfetch: -catalog: %v\n", err)
		return nil, 0, 0, 2
	}
	cat, err := bottle.UnmarshalCatalog(raw)
	if err != nil {
		fmt.Fprintf(stderr, "vulnfetch: -catalog %s: %v\n", path, err)
		return nil, 0, 0, 2
	}
	published := map[string]string{}
	for _, p := range cat.Projects {
		if len(p.Versions) > 0 {
			published[p.Project] = p.Versions[0]
		}
	}
	at := 0
	for _, id := range ids {
		v := ""
		// ⛔ TWO REASONS FOR AN EMPTY VERSION, AND THEY ARE NOT THE SAME.
		// Nothing published for this platform means the project is out of
		// scope here; two projects disagreeing about the version means there
		// is no single one to ask about and the question must widen. Treating
		// both as "ask about the whole package" is what made the first run
		// report 90 findings across 5 projects that this platform does not
		// carry — figures that were right and meant something else.
		anyPublished, conflict := false, false
		for _, project := range byIdentity[id] {
			pv := published[project]
			if pv == "" {
				continue
			}
			anyPublished = true
			if v != "" && v != pv {
				conflict = true
				break
			}
			v = pv
		}
		if conflict {
			v = "" // ask about the package: under-reporting would hide one
		}
		if !anyPublished {
			// Not asked at all. A vulnerability in something we do not ship
			// is not a finding about us, and 90 of them drowned the one
			// question that mattered.
			unpublished++
			continue
		}
		// ⛔ COUNT ONLY WHAT WILL ACTUALLY BE ASKED. The first version of this
		// counted every pinned identity, including the repository- and
		// CPE-keyed ones that AskPinned drops before the request — and
		// printed "1217 of them asked AT the version" one line above "171
		// identity(ies) asked". A number larger than the total it is a
		// subset of is not a rounding problem, it is a different population.
		if v != "" && vuln.Queryable(id) {
			at++
		}
		out = append(out, vuln.Pinned{Identity: id, Version: v})
	}
	return out, at, unpublished, 0
}
