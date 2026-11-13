package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/fixup"
)

// rpathRefRE pulls the project out of an @rpath reference: the segments before
// the version directory. A project name has slashes in it (gnupg.org/gpgme),
// so the version directory is the only reliable terminator.
var rpathRefRE = regexp.MustCompile(`^@rpath/(.+?)/v[0-9][^/]*/`)

// ownerRE reads the project out of a store-relative path: everything before
// the version directory. Compiled once; the walk asks it per file.
var ownerRE = regexp.MustCompile(`^(.+?)/v[0-9][^/]*/`)

// Seams: the two things here that need a network.
var (
	undeclaredGraph             = bottle.GraphFor
	undeclaredInstall           = bottle.CompleteClosure
	undeclaredTempDir           = os.MkdirTemp
	undeclaredStdin   io.Reader = os.Stdin
)

// runUndeclared implements `bk undeclared`: which projects does a bottle LINK
// without declaring?
//
// This is the CAUSE whose symptom `closurecheck` reports. gnupg.org/gpgme
// declares libgpg-error under build.dependencies and nowhere else, so a closure
// that installs gpgme gets none of it — and libgpgme.11.dylib names it anyway:
//
//	@rpath/gnupg.org/libgpg-error/v1.61.0/lib/libgpg-error.0.dylib
//
// It goes unnoticed because the reference usually RESOLVES: some other package
// in the same closure pulled the dependency in. It breaks only in a closure
// that has the culprit and not the rescuer, which is where poppler's build
// found it — g-ir-scanner died loading the chain, naming a .gir target and
// nothing about a declaration.
//
// Two things this does NOT do, both learned from getting them wrong in a
// throwaway script first:
//
//   - It scans every project in the store, not only the one it was asked for.
//     A dependency's mis-declaration is invisible from the package that happens
//     to pull it in, and gpgme and libassuan are nobody's audited root.
//   - It reads the Mach-O itself rather than shelling out to otool, which is an
//     Xcode tool and absent from the FROM-scratch image this factory builds in.
//   - It reads what a file LOADS, not every load-command string: the install
//     name is not a dependency, and counting it makes a library appear to
//     depend on wherever it happens to live.
func runUndeclared(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("undeclared", flag.ContinueOnError)
	fset.SetOutput(stderr)
	store := fset.String("store", "", "install into this directory (default: a temporary one, removed after)")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	projects, err := undeclaredProjects(fset.Args(), undeclaredStdin)
	if err != nil {
		fmt.Fprintln(stderr, "undeclared:", err)
		return 1
	}
	if len(projects) == 0 {
		fmt.Fprintln(stderr, "undeclared: no projects (name them, or pipe them in)")
		return 2
	}

	dir := *store
	if dir == "" {
		d, err := undeclaredTempDir("", "bk-undeclared-")
		if err != nil {
			fmt.Fprintln(stderr, "undeclared:", err)
			return 1
		}
		dir = d
		defer os.RemoveAll(dir)
	}

	osn, arch := bottle.HostSlug()
	seen := map[string]bool{}
	total := 0
	for _, p := range projects {
		roots := map[string]string{p: "*"}
		g, err := undeclaredGraph(roots, osn, arch)
		if err != nil {
			fmt.Fprintf(stderr, "undeclared: %s: %v\n", p, err)
			continue
		}
		if _, err := undeclaredInstall(roots, dir); err != nil {
			fmt.Fprintf(stderr, "undeclared: %s: %v\n", p, err)
			continue
		}
		byOwner := refsByOwner(dir)
		for _, owner := range sortedOwners(byOwner) {
			if seen[owner] {
				continue
			}
			seen[owner] = true
			miss := undeclaredOf(owner, byOwner[owner], g)
			if len(miss) == 0 {
				continue
			}
			total += len(miss)
			fmt.Fprintf(stdout, "%-34s links but does not declare: %s\n", owner, strings.Join(miss, ", "))
		}
	}
	fmt.Fprintf(stdout, "\n%d undeclared edge(s)\n", total)
	if total > 0 {
		return 1
	}
	return 0
}

// undeclaredProjects reads the list from the arguments, or from stdin when
// there are none, so recipes.txt feeds it unchanged.
func undeclaredProjects(args []string, in io.Reader) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	var out []string
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line)[0])
	}
	return out, sc.Err()
}

// refsByOwner maps each project in the store onto the projects its own Mach-O
// files reference.
func refsByOwner(dir string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		// TrimPrefix, not filepath.Rel: the walk is rooted at dir, so every
		// path it yields is under it and Rel has no failure to report.
		rel := strings.TrimPrefix(strings.TrimPrefix(p, dir), string(filepath.Separator))
		owner, ok := ownerOf(rel)
		if !ok {
			return nil
		}
		strs, serr := fixup.MachoNeeded(p)
		if serr != nil {
			return nil // not a Mach-O, or unreadable: neither is an edge
		}
		for _, s := range strs {
			if m := rpathRefRE.FindStringSubmatch(s); m != nil {
				if out[owner] == nil {
					out[owner] = map[string]bool{}
				}
				out[owner][m[1]] = true
			}
		}
		return nil
	})
	return out
}

// ownerOf reads the project out of a store-relative path: everything before
// the version directory.
func ownerOf(rel string) (string, bool) {
	m := ownerRE.FindStringSubmatch(filepath.ToSlash(rel))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// undeclaredOf is what owner references and cannot reach through the
// declarations, itself excluded.
//
// Reachability is transitive on purpose: rust-lang.org/cargo links libssh2 and
// openssl and declares neither, because libgit2.org brings both and says so.
// That is a declaration, one hop further out, and calling it a defect was what
// made the first version of this over-report.
func undeclaredOf(owner string, refs map[string]bool, g *bottle.Graph) []string {
	reach := map[string]bool{owner: true}
	queue := []string{owner}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, e := range g.Deps[n] {
			if !reach[e.On] {
				reach[e.On] = true
				queue = append(queue, e.On)
			}
		}
	}
	var out []string
	for r := range refs {
		if !reach[r] {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

func sortedOwners(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
