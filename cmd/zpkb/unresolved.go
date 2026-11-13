package main

import (
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
)

// unresolvedPrefixRE matches a store-relative VERSION directory — the prefix a
// soname search looks under. It anchors on the trailing slash the caller adds,
// so "a.org/v1" matches and "a.org/v1/lib" does not.
var unresolvedPrefixRE = regexp.MustCompile(`^(.+?)/v[0-9][^/]*/$`)

// unresolvedOwnerRE reads the project out of a store-relative path: everything
// before the version directory. A project name has slashes in it —
// gnupg.org/gpgme — so that directory is the only reliable terminator.
var unresolvedOwnerRE = regexp.MustCompile(`^(.+?)/v[0-9][^/]*/`)

// Seams: the two things here that need a network.
var (
	unresolvedInstall           = bottle.CompleteClosureFor
	unresolvedTempDir           = os.MkdirTemp
	unresolvedStdin   io.Reader = os.Stdin
)

// runUnresolved implements `bk unresolved`: which @rpath references in an
// installed closure name a file the store does not have?
//
// It is the SYMPTOM whose cause `bk undeclared` reports, and the two answer
// different questions. A missing declaration is a packaging defect; an
// unresolvable reference is what the loader will actually refuse, and a bottle
// can have one without the other — a reference to a version directory that
// moved on is declared perfectly and still resolves nowhere.
//
// Each project is installed into its OWN store. A shared one rescues
// references by accident: gpgme's undeclared libgpg-error resolved for months
// because something else in the same closure happened to bring it, and the
// failure only appeared in a closure that had gpgme and not the rescuer.
//
// It reads the Mach-O itself rather than shelling out to otool, which is an
// Xcode tool and absent from the FROM-scratch image this factory builds in.
// This command exists BECAUSE a lab binary answering the same question turned
// out to be two days old with its source lost — a tool built before the fix it
// measures gives verdicts that are plausible and wrong.
func runUnresolved(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("unresolved", flag.ContinueOnError)
	fset.SetOutput(stderr)
	store := fset.String("store", "", "install into this directory (default: a temporary one, removed after)")
	quiet := fset.Bool("quiet", false, "print only the projects that have unresolvable references")
	// ⛔ ONE MACHINE, EVERY PLATFORM. Until bottle v0.55.0 this installed for
	// the HOST, so the sweep that uses it (go-zpkg/packages sonames.yml)
	// could only ask about linux/x86-64 — where it found 967 unresolvable
	// references over 259 of 1407 bottled projects. The other five were not
	// clean; they were unasked, which is the shape a CVE lane here spent two
	// months in.
	//
	// The READER was already platform-blind: unresolvedByOwner walks ELF and
	// Mach-O in one pass precisely because a store built on one platform is
	// read on another. Only the install half was host-bound.
	platform := fset.String("platform", "", "audit this os/arch (e.g. linux/aarch64) instead of the host's")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	osn, arch := bottle.HostSlug()
	if *platform != "" {
		o, a, ok := strings.Cut(*platform, "/")
		if !ok || o == "" || a == "" {
			// A half-parsed platform would resolve against an empty arch and
			// report every bottle as absent — a clean-looking catastrophe.
			fmt.Fprintf(stderr, "unresolved: %q is not an os/arch\n", *platform)
			return 2
		}
		osn, arch = o, a
	}
	projects, err := undeclaredProjects(fset.Args(), unresolvedStdin)
	if err != nil {
		fmt.Fprintln(stderr, "unresolved:", err)
		return 1
	}
	if len(projects) == 0 {
		fmt.Fprintln(stderr, "unresolved: no projects (name them, or pipe them in)")
		return 2
	}

	total := 0
	for _, p := range projects {
		dir := *store
		if dir == "" {
			d, err := unresolvedTempDir("", "bk-unresolved-")
			if err != nil {
				fmt.Fprintln(stderr, "unresolved:", err)
				return 1
			}
			dir = d
			defer os.RemoveAll(dir)
		}
		if _, err := unresolvedInstall(map[string]string{p: "*"}, dir, osn, arch); err != nil {
			fmt.Fprintf(stderr, "unresolved: %s: %v\n", p, err)
			continue
		}
		byOwner := unresolvedByOwner(dir)
		n := 0
		for _, owner := range sortedOwners2(byOwner) {
			refs := byOwner[owner]
			if len(refs) == 0 {
				continue
			}
			n += len(refs)
			fmt.Fprintf(stdout, "%-34s %-34s %d unresolvable\n", p, owner, len(refs))
			if !*quiet {
				for _, r := range refs {
					fmt.Fprintf(stdout, "    %s\n", r)
				}
			}
		}
		if n == 0 && !*quiet {
			fmt.Fprintf(stdout, "%-34s ok\n", p)
		}
		total += n
	}
	fmt.Fprintf(stdout, "\n%d unresolvable reference(s)\n", total)
	if total > 0 {
		return 1
	}
	return 0
}

// unresolvedByOwner maps each project in the store onto the references its own
// binaries name and the store cannot answer.
//
// The two formats ask differently shaped questions, and the answer has to be
// shaped to match. A Mach-O names a PATH, so "is it satisfied" is a stat:
// either the store has that file or the program does not start. An ELF names a
// SONAME and the loader searches for it, so the question is whether ANYTHING
// in the closure provides that name — which cannot be answered file by file,
// only once the whole store has been walked.
//
// Doing both in one pass matters more than it looks: a store built on one
// platform is read on another all the time, and an audit that understands only
// the host's format reports a linux closure as flawless because it could not
// read a single file in it.
func unresolvedByOwner(dir string) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	// ELF: the soname each owner needs, resolved against the whole store after
	// the walk. Kept in order so the report does not move between runs.
	type want struct{ owner, soname string }
	var elfWants []want
	var prefixes []string

	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(p, dir), string(filepath.Separator)))
		if d.IsDir() {
			// A version directory is a prefix a soname search may look in.
			if m := unresolvedPrefixRE.FindStringSubmatch(rel + "/"); m != nil {
				prefixes = append(prefixes, p)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		m := unresolvedOwnerRE.FindStringSubmatch(rel)
		if m == nil {
			return nil
		}
		owner := m[1]
		if refs, rerr := bottle.MachoNeeded(p); rerr == nil {
			if _, ok := out[owner]; !ok {
				out[owner] = nil // examined, even if clean
			}
			for _, ref := range refs {
				if !strings.HasPrefix(ref, "@rpath/") {
					continue // /usr/lib and the system frameworks are the host's
				}
				if _, serr := os.Stat(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(ref, "@rpath/")))); serr == nil {
					continue
				}
				// One line per (owner, reference): the same reference from
				// forty binaries is forty occurrences of ONE defect, and
				// printing all of them buries the count that matters.
				key := owner + "\x00" + ref
				if seen[key] {
					continue
				}
				seen[key] = true
				out[owner] = append(out[owner], ref)
			}
			return nil
		}
		if sonames, eerr := bottle.ELFNeeded(p); eerr == nil {
			if _, ok := out[owner]; !ok {
				out[owner] = nil
			}
			for _, s := range sonames {
				elfWants = append(elfWants, want{owner, s})
			}
		}
		return nil
	})

	if len(elfWants) > 0 {
		have := bottle.SonamesUnder(prefixes)
		for _, w := range elfWants {
			if have[w.soname] || bottle.SonameComesFromOutside(w.soname) {
				continue
			}
			key := w.owner + "\x00" + w.soname
			if seen[key] {
				continue
			}
			seen[key] = true
			out[w.owner] = append(out[w.owner], w.soname)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func sortedOwners2(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
