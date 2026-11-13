package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/go-zpkg/bottle"
)

// ⛔ A LOCK PINNED WHAT COULD NOT BE INSTALLED, AND SAID NOTHING.
//
// `bk lock` resolves a version from the recipe's `versions:` block. It never
// asks the registry, so it pins the newest version the recipes can BUILD —
// which by construction runs ahead of what the factory has PUBLISHED.
//
// Measured 2026-10-09 by generating a real lock and running it:
//
//	$ bk lock -platform linux/aarch64 -o curl.lock.hcl curl.se
//	lock: 5 project(s) pinned → curl.lock.hcl
//
//	$ pkgx --lock curl.lock.hcl curl --version      # FROM-scratch container
//	pkgx: no version of curl.se/ca-certs satisfies "=2026.09.25" AND is
//	published for linux/aarch64
//
// Two pins of five — curl.se/ca-certs 2026.09.25 against 2026.8.13
// published, openssl.org 4.0.3 against 4.0.2. The lock's own header promised
// that `pkgx --lock` runs it. Nothing in writing it said otherwise.
//
// # THE TWO USES ARE DIFFERENT QUESTIONS
//
// `bk factory --lock` is about to BUILD these versions, so a pin ahead of the
// registry is exactly right there. `pkgx --lock` can only install what
// exists. One file cannot answer both by accident, so it now answers one of
// them on purpose: `-runnable` pins what is published, the default pins what
// the recipes build, and either way the unpublished pins are NAMED at write
// time rather than discovered by whoever tries to use the file.
//
// # publishedTagFor IS THE ONLY INSTRUMENT THAT CAN ANSWER THIS
//
// Three others look like they can and cannot: the catalogue carries one
// version per project, bottle.VersionsFor spans every platform (our registry's
// tag listing is not per-platform), and `crane ls` shows only the suffixed
// tags while publication may live in the unsuffixed index.
var (
	lockPublishedTagFor = bottle.PublishedTagFor
	lockPickPublished   = bottle.PickVersionFor
	// PickVersionForAll, not PickVersionFor: see publishedVersionFor.
	lockPickPublishedAll = bottle.PickVersionForAll
)

// unpublishedPin is a pin the named platform cannot install.
type unpublishedPin struct {
	Project string
	Locked  string
	// Published is the newest version that IS published there, or "" when
	// the registry carries none at all — a different situation, and the
	// report says which.
	Published string
}

// unpublishedPins asks, for every pin, whether that exact version is
// published for os/arch.
//
// An error from the registry is NOT silently treated as "published": a lookup
// that could not be made says nothing either way, and reporting it as clean
// is how a check becomes decoration. It is reported as its own line.
func unpublishedPins(pins []lockedPin, osn, arch string) (bad []unpublishedPin, failed []string) {
	for _, p := range pins {
		tag, ok, err := lockPublishedTagFor(p.Project, bottle.ParseVer(p.Version), osn, arch)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", p.Project, err))
			continue
		}
		if ok && tag != "" {
			continue
		}
		u := unpublishedPin{Project: p.Project, Locked: p.Version}
		if v, err := lockPickPublished(p.Project, "*", osn, arch); err == nil {
			u.Published = v.Raw
		}
		bad = append(bad, u)
	}
	sort.Slice(bad, func(i, j int) bool { return bad[i].Project < bad[j].Project })
	return bad, failed
}

// reportUnpublished writes the verdict, and ALWAYS writes one.
//
// A line saying every pin is installable is the point of the exercise: the
// defect this replaces was a silence, and replacing a silence with a
// conditional message leaves the clean case indistinguishable from a version
// of bk that does not check at all.
func reportUnpublished(w io.Writer, pins []lockedPin, bad []unpublishedPin, failed []string, platform, mode string, holes int) {
	for _, f := range failed {
		fmt.Fprintf(w, "lock: could NOT be asked about — this is not an all-clear: %s\n", f)
	}
	// ⛔ A COUNT CANNOT SEE WHAT IS MISSING. Measured 2026-10-09: openssl.org
	// resolved to nothing a `-runnable` lock could install, so it was dropped
	// and the file held four pins — under the line "4 of 4 pin(s) published
	// — `pkgx --lock` can run this file". Every pin present was installable
	// and the sentence was true; the lock was still a closure with a hole in
	// it. The exit status already said so, and the prose contradicted it.
	if holes > 0 {
		fmt.Fprintf(w, "lock: %d project(s) could not be pinned at all (named above) — this file is NOT a closure, whatever its pins say\n", holes)
		return
	}
	// ⛔ ZERO PINS IS NOT A CLEAN VERDICT. "0 of 0 published — pkgx can run
	// this file" is what this printed when every project failed to resolve,
	// which is the same shape as the silence it replaces: a true sentence
	// about an empty set, read as an endorsement. Seen in a test's failure
	// output, not reasoned about.
	if len(pins) == 0 {
		fmt.Fprintf(w, "lock: nothing was pinned, so there is nothing to say about %s\n", platform)
		return
	}
	if len(bad) == 0 && len(failed) == 0 {
		fmt.Fprintf(w, "lock: %d of %d pin(s) published for %s — `pkgx --lock` can run this file\n",
			len(pins), len(pins), platform)
		return
	}
	if len(bad) > 0 {
		fmt.Fprintf(w, "lock: %d of %d pin(s) NOT published for %s — `bk factory --lock` can build this file, `pkgx --lock` cannot run it:\n",
			len(bad), len(pins), platform)
		for _, u := range bad {
			here := "nothing published here"
			if u.Published != "" {
				here = "published here: " + u.Published
			}
			fmt.Fprintf(w, "    %-28s %-14s (%s)\n", u.Project, u.Locked, here)
		}
		if mode != bottle.PinsPublished {
			fmt.Fprintln(w, "    `bk lock -runnable` pins what is published instead.")
		}
	}
}

// lockModeOf names the mode for the lock document and for the report.
func lockModeOf(runnable bool) string {
	if runnable {
		return bottle.PinsPublished
	}
	return bottle.PinsFromRecipes
}

// publishedVersionFor is the `-runnable` resolver: the newest version
// published for this platform that satisfies every demand the closure places
// on this project.
//
// ⛔ THE CONSTRAINTS ARE NOT OPTIONAL HERE, and the first version of this
// function dropped them — it asked for "*", reasoning that "the newest one
// that runs" beat "no runnable lock exists". Measured 2026-10-09, by running
// the lock it produced in a FROM-scratch container:
//
//	$ bk lock -runnable -platform linux/aarch64 curl.se
//	lock: 5 of 5 pin(s) published for linux/aarch64 — `pkgx --lock` can run this file
//
//	$ pkgx --lock curl-run.lock.hcl curl --version
//	pkgx: no version of openssl.org satisfies "=4.0.2" AND "^3";
//	asked for by =4.0.2 (requested), ^3 (curl.se)
//
// curl.se 8.20 demands openssl ^3; the newest PUBLISHED openssl is 4.0.2. A
// per-project "newest published" is not a closure — it pins a set that cannot
// resolve, under a line claiming pkgx can run it, which is worse than either
// honest answer.
//
// PickVersionForAll is the function the resolver itself asks, so the lock
// answers the same question pkgx will.
func publishedVersionFor(project string, constraints []string, osn, arch string) (string, error) {
	v, err := lockPickPublishedAll(project, constraints, osn, arch)
	if err != nil {
		return "", err
	}
	return v.Raw, nil
}
