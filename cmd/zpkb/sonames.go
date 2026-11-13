package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/artifact"
)

// runSonames implements `bk sonames`: which shared library does a set of
// PUBLISHED artifacts need that none of them provides.
//
// `bk builder` answers this for a STAGED tree, and that is the right question
// for a rootfs. It is not the right question for a registry, because the two
// are not the same set and cannot be: a seed order is a BUILD order, not a
// coexisting one. Measured on go-zpkg/packages' 78 — cmake.org wants
// curl.se `>=5<8.13` and rust-lang.org/cargo wants `8`, and no published
// version satisfies both, so there is no tree that holds them all.
//
// So each artifact is unpacked ON ITS OWN and the two sets are unioned. That
// answers "which soname does NOBODY here provide", which is the shape of the
// defect this exists for: an artifact built on a host that HAS libselinux links
// it, and nothing in this factory ships it. It does NOT answer "does each
// artifact's DECLARED closure suffice" — that is `bk undeclared`, and it is a
// stricter and more expensive question.
//
// Reported, never fatal, like the staged-tree census: a sweep that can fail a
// pipeline is one nobody runs.
func runSonames(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sonames", flag.ContinueOnError)
	fs.SetOutput(stderr)
	platform := fs.String("platform", envOr("PLATFORM", "linux/x86-64"), "target os/arch")
	dist := fs.String("dist", "", "artifact registry to read from (default $ZPKG_DIST)")
	list := fs.String("list", "", "file of `project[constraint]` lines, one per line, # comments — a seed order will do")
	keep := fs.String("keep", "", "unpack into this directory instead of a temporary one, and leave it behind")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	if *dist != "" {
		artifact.DistBase = strings.TrimRight(*dist, "/")
	}

	roots, err := sonameRoots(*list, fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "sonames:", err)
		return 2
	}

	dir := *keep
	if dir == "" {
		d, err := osMkdirTemp("", "bk-sonames-")
		if err != nil {
			fmt.Fprintln(stderr, "sonames:", err)
			return 1
		}
		defer os.RemoveAll(d)
		dir = d
	}

	provided := map[string]bool{}
	needed := map[string][]string{}
	var unreadable []string
	names := make([]string, 0, len(roots))
	for p := range roots {
		names = append(names, p)
	}
	sort.Strings(names)

	for _, proj := range names {
		// Its OWN directory, so two projects that demand incompatible
		// versions of a third never meet. The union below is what makes that
		// sound: a library provided anywhere counts as provided.
		one := filepath.Join(dir, strings.ReplaceAll(proj, "/", "_"))
		r, err := resolveOne(proj, roots[proj], osn, arch)
		if err != nil {
			// Said, never silent. A project that cannot be resolved is not a
			// project without a missing soname — it is one nobody looked at,
			// and a census that drops it quietly reports a smaller number for
			// the wrong reason.
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", proj, err))
			continue
		}
		if _, err := installFor(r, one, osn, arch); err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s %s: %v", proj, r.Version.Raw, err))
			continue
		}
		pr, nd := scanSonames(one)
		for k := range pr {
			provided[k] = true
		}
		for k, who := range nd {
			for _, w := range who {
				needed[k] = append(needed[k], proj+":"+filepath.Base(w))
			}
		}
	}

	fmt.Fprintf(stdout, "sonames: %d of %d project(s) read for %s\n", len(names)-len(unreadable), len(names), *platform)
	for _, u := range unreadable {
		fmt.Fprintln(stdout, "  UNREAD", u)
	}
	// A set with no libc in it reports libc.so.6 missing, correctly and
	// uselessly. Say so rather than let the reader discover it: the census
	// answers "nobody HERE provides this", and `here` is whatever was named.
	if _, ok := roots[artifact.GlibcProject]; !ok {
		fmt.Fprintf(stdout, "  note: %s is not in this set, so its libraries will read as missing\n", artifact.GlibcProject)
	}
	fmt.Fprintln(stdout, reportSonames("sonames", provided, needed, dir))
	return 0
}

// sonameRoots takes the projects from a file, from the command line, or both.
func sonameRoots(list string, args []string) (map[string]string, error) {
	roots := map[string]string{}
	if list != "" {
		b, err := os.ReadFile(list)
		if err != nil {
			return nil, err
		}
		for _, ln := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
			if ln = strings.TrimSpace(ln); ln == "" {
				continue
			}
			proj, c := splitToolchainSpec(ln)
			roots[proj] = c
		}
	}
	for _, a := range args {
		proj, c := splitToolchainSpec(a)
		roots[proj] = c
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("name a project, or point --list at a file of them")
	}
	return roots, nil
}

// resolveOne picks the version of ONE project, without its closure: the
// question here is what each artifact itself carries, and resolving a closure
// would both cost more and make a dependency's library count as this
// package's own.
var resolveOne = func(proj, constraint, osn, arch string) (artifact.Resolved, error) {
	clo, err := resolveClosureFor(map[string]string{proj: constraint}, osn, arch)
	if err != nil {
		return artifact.Resolved{}, err
	}
	for _, r := range clo {
		if r.Project == proj {
			return r, nil
		}
	}
	return artifact.Resolved{}, fmt.Errorf("resolved a closure that does not contain %s", proj)
}

// osMkdirTemp is a seam: a census that cannot make a directory must say so,
// and that branch is not reachable with a real filesystem.
var osMkdirTemp = os.MkdirTemp
