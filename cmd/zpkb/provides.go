package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/go-zpkg/bottle"
)

// Seams, the same shape `unlinked` has, so the command is driven without a
// network.
var (
	providesInstall = bottle.CompleteClosureFor
	providesTempDir = os.MkdirTemp
)

// runProvides implements `bk provides`: does a published bottle's bin/ say the
// same thing as the `provides` its catalogue entry states?
//
// ⛔ NOTHING COMPARED THEM, AND BOTH DIRECTIONS SHIPPED WRONG (go-zpkg/bk#376).
// In the published wasip1/wasm catalogue of 2026-10-31:
//
//	zlib.net        ships bin/minigzip.wasm and lists NO command at all
//	filippo.io/age  lists age-keygen; the bottle has no bin/age-keygen.wasm
//
// They are different failures and are reported apart, never as one "mismatch"
// count, because they hurt different people:
//
//	listed, no file   `pkgx -Q age-keygen` names a package that CANNOT supply
//	                  it: someone installs it and the command is still missing.
//	file, not listed  a command that exists and is invisible to `pkgx -Q`,
//	                  `pkgs search` and the <TAB> index: the package might as
//	                  well not exist for every reader we ship.
//
// WHY IN bk. The comparison needs the catalogue types, the platform-explicit
// closure install (bottle.CompleteClosureFor, the one `unlinked` and
// `unresolved` use to audit a platform other than the host's) and the same
// `provides` reduction `bk catalog` applied, all of which live here. A workflow
// then runs `bk provides --fail` beside `bk catalog`; it does not need to know
// how a bottle is unpacked.
//
// WHAT COUNTS AS A COMMAND. A regular file or symlink directly in
// <version>/bin, with the platform's executable suffix removed: `.wasm` on
// wasip1 (provides says bin/minigzip, the bottle carries minigzip.wasm) and
// `.exe` on windows. Dot-files are not commands. Only bin/ is compared,
// because ProvidedCommands only ever reports bin/ entries.
func runProvides(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("provides", flag.ContinueOnError)
	fset.SetOutput(stderr)
	catPath := fset.String("catalog", "", "the catalogue to check: catalog.json, or the catalogue bottle's .tar.gz (required)")
	store := fset.String("store", "", "install into this directory (default: a temporary one, removed after)")
	platform := fset.String("platform", "", "check this os/arch instead of the host's")
	failOn := fset.Bool("fail", false, "exit 1 if anything is found")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if *catPath == "" {
		fmt.Fprintln(stderr, "provides: --catalog is required")
		return 2
	}
	osn, arch := bottle.HostSlug()
	if *platform != "" {
		o, a, ok := strings.Cut(*platform, "/")
		if !ok || o == "" || a == "" {
			fmt.Fprintf(stderr, "provides: --platform %q is not os/arch\n", *platform)
			return 2
		}
		osn, arch = o, a
	}
	cat, err := readCatalogFile(*catPath)
	if err != nil {
		fmt.Fprintln(stderr, "provides:", err)
		return 1
	}

	projects := fset.Args()
	if len(projects) == 0 {
		// Every project the catalogue says is installable HERE: a named
		// project with no version has no bottle, so there is nothing to open.
		for _, e := range cat.Projects {
			if len(e.Versions) > 0 {
				projects = append(projects, e.Project)
			}
		}
	}
	if len(projects) == 0 {
		fmt.Fprintln(stderr, "provides: no projects (name them, or give a catalogue that has published versions)")
		return 2
	}

	dir := *store
	if dir == "" {
		d, err := providesTempDir("", "bk-provides-")
		if err != nil {
			fmt.Fprintln(stderr, "provides:", err)
			return 1
		}
		dir = d
		defer os.RemoveAll(dir)
	}

	var noFile, notListed, unreadable int
	for _, p := range projects {
		entry, ok := cat.Lookup(p)
		if !ok {
			fmt.Fprintf(stderr, "provides: %s: not in the catalogue\n", p)
			unreadable++
			continue
		}
		res, err := providesInstall(map[string]string{p: "*"}, dir, osn, arch)
		if err != nil {
			fmt.Fprintf(stderr, "provides: %s: %v\n", p, err)
			unreadable++
			continue
		}
		prefix := ""
		for _, r := range res {
			if r.Project == p {
				prefix = filepath.Join(dir, filepath.FromSlash(p), "v"+r.Version.Raw)
			}
		}
		if prefix == "" {
			fmt.Fprintf(stderr, "provides: %s: installed, but the closure does not name it\n", p)
			unreadable++
			continue
		}
		listedOnly, shippedOnly, err := compareProvides(entry.Provides, prefix, osn)
		if err != nil {
			fmt.Fprintf(stderr, "provides: %s: %v\n", p, err)
			unreadable++
			continue
		}
		for _, c := range listedOnly {
			noFile++
			fmt.Fprintf(stdout, "%-34s LISTED, NO FILE   provides %q but the bottle has no bin/%s\n", p, c, c+exeSuffix(osn))
		}
		for _, c := range shippedOnly {
			notListed++
			fmt.Fprintf(stdout, "%-34s FILE, NOT LISTED  bin/%s is in the bottle and `provides` omits %q\n", p, c+exeSuffix(osn), c)
		}
	}
	fmt.Fprintf(stdout, "\n%d listed with no file (an install that cannot supply the command)\n", noFile)
	fmt.Fprintf(stdout, "%d file(s) not listed (a command no reader can find by name)\n", notListed)
	if unreadable > 0 {
		fmt.Fprintf(stdout, "%d project(s) could not be checked\n", unreadable)
	}
	if *failOn && noFile+notListed+unreadable > 0 {
		return 1
	}
	return 0
}

// readCatalogFile reads a catalogue from catalog.json or from the catalogue
// bottle's tarball, told apart by name.
func readCatalogFile(path string) (bottle.Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return bottle.Catalog{}, err
	}
	if strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz") {
		return bottle.CatalogFromTarball(b)
	}
	return bottle.UnmarshalCatalog(b)
}

// exeSuffix is what a platform appends to a command's file name.
func exeSuffix(osn string) string {
	switch osn {
	case "wasip1":
		return ".wasm"
	case "windows":
		return ".exe"
	}
	return ""
}

// compareProvides sets a catalogue entry's stated commands against the files
// in prefix/bin, and returns the two differences separately, sorted: commands
// listed with no file behind them, and files with no entry listing them.
//
// A prefix with no bin/ directory is a bottle with no commands, which is a
// legitimate library, not an error; any other read failure is an error,
// because a bin/ that could not be read would otherwise report every listed
// command as missing.
func compareProvides(provides []string, prefix, osn string) (listedOnly, shippedOnly []string, err error) {
	suffix := exeSuffix(osn)
	var shipped []string
	ents, err := os.ReadDir(filepath.Join(prefix, "bin"))
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") {
			continue
		}
		if suffix != "" {
			// Only a file WITH the suffix is a command on this platform; a
			// stray bin/README on wasip1 is not one.
			if !strings.HasSuffix(n, suffix) {
				continue
			}
			n = strings.TrimSuffix(n, suffix)
		}
		shipped = append(shipped, n)
	}
	for _, c := range provides {
		if !slices.Contains(shipped, c) {
			listedOnly = append(listedOnly, c)
		}
	}
	for _, c := range shipped {
		if !slices.Contains(provides, c) {
			shippedOnly = append(shippedOnly, c)
		}
	}
	sort.Strings(listedOnly)
	sort.Strings(shippedOnly)
	return listedOnly, shippedOnly, nil
}
