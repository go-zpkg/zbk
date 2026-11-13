package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
	"github.com/go-zpkg/zpkb/versions"
)

// lockedPin and lockDoc are artifact's types under the names this file has
// always used.
//
// The FORMAT moved to artifact so that pkgx could read a lock at all: the
// reader lived in this `package main`, which is importable by nothing, and
// a lock only means something once something ELSE acts on it. The
// RESOLUTION stays here, because deciding what a set means today needs a
// pantry, an overrides set and a version resolver, none of which belong in
// an artifact client.
//
// Aliases rather than a rename, so this diff is the move and nothing else.
type lockedPin = artifact.LockPin
type lockDoc = artifact.Lock

// lockfileVersion is artifact's, so a bump cannot be made in one repository
// and missed in the other.
const lockfileVersion = artifact.LockfileVersion

// bkVersion is the module version of the running bk, which is what Spack
// records for the same reason: a lock is evidence about a resolution, and the
// resolver is part of it. A local build has no version stamped in, and saying
// `(devel)` is more honest than leaving the field out.
func bkVersion() string {
	if bi, ok := buildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(unknown)"
}

// buildInfo is a seam: a test binary's own build info is not bk's, and both
// branches above have to be reachable.
var buildInfo = debug.ReadBuildInfo

// resolveLock turns a closure order into pins, hashing as it goes.
//
// `order` is topological, deps first, so a dependency's spec hash is always
// already in hand when its dependent is hashed. That is why this loop is not
// sorted and the OUTPUT is.
// resolveLock pins every project in order.
//
// runnable chooses WHICH QUESTION the versions answer: false pins the newest
// the recipes can build (what `bk factory --lock` is about to build), true
// pins the newest published for the target (what `pkgx --lock` can install).
// They are different sets — see lockpublished.go, where the measurement is.
// rootPins carries the constraint a ROOT was named with, if any.
//
// ⛔ ONLY a root's own, and only one. `versions.Resolve` takes a single
// constraint while `demands` is a list, and folding several into one is the
// intersection problem of go-zpkg/bk#140 — not something to invent here. A
// root is the case where there is exactly one and nothing else speaks for it,
// so it is the case that can be fixed without pretending to solve the rest.
func resolveLock(set *logical.Set, overlayDir, pantryDir string, tgt target.Target,
	order []string, demands map[string][]string, read map[string][]*pantry.Recipe, runnable bool,
	rootPins map[string]string) ([]lockedPin, []string) {
	var pins []lockedPin
	var unresolved []string
	hashes := map[string]string{}
	for _, proj := range order {
		r, _, err := recipeLoader(set, overlayDir, pantryDir, proj)
		if err != nil || r == nil {
			unresolved = append(unresolved, fmt.Sprintf("%s (no recipe: %v)", proj, err))
			continue
		}
		v, _, err := versions.Resolve(r.Versions, rootPins[proj])
		if err != nil || v == "" {
			unresolved = append(unresolved, fmt.Sprintf("%s (%v)", proj, err))
			continue
		}
		if runnable {
			// A project with nothing published for this platform is a HOLE
			// in a runnable lock, not a pin to quietly leave at the recipe's
			// version: the whole promise of the mode is that `pkgx --lock`
			// can install every line.
			pv, perr := publishedVersionFor(proj, demands[proj], tgt.Platform, tgt.Arch)
			if perr != nil {
				unresolved = append(unresolved, fmt.Sprintf("%s (nothing published for %s/%s: %v)", proj, tgt.Platform, tgt.Arch, perr))
				continue
			}
			v = pv
		}
		// The recipes the closure itself read. Not re-read: the walk already
		// has them, and a project whose recipes do not load never reaches
		// `order`, so a second read could only fail in ways nothing can test.
		recs := read[proj]
		sh, err := specHash(recs, proj, v, tgt, hashes, specDeps(recs, tgt))
		if err != nil {
			unresolved = append(unresolved, fmt.Sprintf("%s (%v)", proj, err))
			continue
		}
		hashes[proj] = sh
		pins = append(pins, lockedPin{Project: proj, Version: v, Spec: sh})
	}
	// Sorted, not closure order: a lock is a SET of facts and is read as a
	// diff. Topological order changes when an unrelated dependency moves, and
	// every line would then appear to have changed.
	sort.Slice(pins, func(i, j int) bool { return pins[i].Project < pins[j].Project })
	return pins, unresolved
}

// renderLock writes the lock, through artifact's one copy of the format.
func renderLock(d lockDoc) string { return artifact.RenderLock(d) }

// readLock parses a lock back, through ARTIFACT's parser and through bk's own
// file seam, so a test that stubs osReadFile still drives this path.
func readLock(path string) (lockDoc, error) {
	src, err := osReadFile(path)
	if err != nil {
		return lockDoc{}, err
	}
	return artifact.ParseLock(src, path)
}

// lockDrift is one disagreement between a lock and today.
type lockDrift struct{ project, was, now string }

// compareLock says what moved between a lock and a fresh resolution.
//
// # THE INTERESTING CASE IS THE ONE A VERSION CANNOT SEE
//
// A project whose VERSION is unchanged and whose SPEC HASH moved is a recipe
// that was edited under a pin. That is the case the spec hash exists for, and
// it is reported in its own words rather than as a hash diff nobody reads.
func compareLock(was, now []lockedPin) []lockDrift {
	index := func(ps []lockedPin) map[string]lockedPin {
		m := make(map[string]lockedPin, len(ps))
		for _, p := range ps {
			m[p.Project] = p
		}
		return m
	}
	a, b := index(was), index(now)
	var out []lockDrift
	for _, p := range was {
		q, ok := b[p.Project]
		if !ok {
			out = append(out, lockDrift{p.Project, p.Version, "(gone from the closure)"})
			continue
		}
		switch {
		case p.Version != q.Version:
			out = append(out, lockDrift{p.Project, p.Version, q.Version})
		case p.Spec != q.Spec:
			out = append(out, lockDrift{p.Project,
				"spec " + shortHash(p.Spec),
				"spec " + shortHash(q.Spec) + " — same version, so something it is built FROM changed"})
		}
	}
	for _, q := range now {
		if _, ok := a[q.Project]; !ok {
			out = append(out, lockDrift{q.Project, "(not in the lock)", q.Version})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].project < out[j].project })
	return out
}

// lockAge says how old a lock is, in artifact's words.
func lockAge(generated string, now time.Time) string { return artifact.LockAge(generated, now) }

// checkLock re-resolves a lock's own roots and says what moved.
//
// # WHOSE IDEA THIS IS
//
// Cargo's `--locked` and npm's `ci` both exist because a lock nobody verifies
// is a lock nobody can rely on: they refuse to run when the lock and a fresh
// resolution disagree. Spack keeps the same shape from the other end — it
// reuses a lockfile's concrete specs unless a run forces re-concretization.
//
// What is reported, and in this order of interest:
//
//	a version that moved          — the ordinary case, and the one a
//	                                version-only lock could also catch
//	a SPEC HASH that moved while  — a recipe edited UNDER a pin. This is the
//	the version did not             case the spec hash exists for, and the
//	                                only one nothing else here can see
//	a project that left or joined — the closure's SHAPE changed
//	a revision that differs       — said, never fatal on its own: a pantry
//	                                can move without moving any answer, and
//	                                calling that drift would make the check
//	                                cry wolf until nobody ran it
func checkLock(want lockDoc, roots []string, pantryDir, overlayDir, overridesDir, platform string,
	stdout, stderr io.Writer) int {
	lset, err := logical.LoadDir(overridesDir)
	if err != nil {
		fmt.Fprintln(stderr, "lock:", err)
		return 2
	}
	osn, arch, _ := strings.Cut(platform, "/")
	tgt := target.Target{Platform: osn, Arch: arch}
	warn := func(s string) { fmt.Fprintln(stderr, s) }

	// ⛔ --check MUST apply the roots' constraints too, and they come from the
	// FILE's own `roots`. Re-resolving `nodejs.org@22` without the `@22` would
	// pick 26 and report drift against a lock that is exactly right — a report
	// of movement that never happened, which is the one thing --check must not
	// produce.
	bare, rootPins := closureRoots(roots, warn)
	expanded := expandSets(lset, overlayDir, pantryDir, bare, warn)
	order, demands, read := closureOf(lset, overlayDir, pantryDir, tgt, expanded, warn)
	if len(order) == 0 {
		fmt.Fprintln(stderr, "lock: the closure is empty — nothing was read, so this says nothing about the lock")
		return 2
	}
	// ⛔ RE-RESOLVE BY THE QUESTION THE FILE ANSWERS, which the file states.
	// Checked by the other question, a lock pinned to published versions
	// reports as drift on every project the recipes have moved ahead of —
	// a report of movement that never happened. `--check` refuses re-stated
	// roots and platform for the same reason, and takes the mode from the
	// file just as it takes those.
	mode := artifact.LockPinned(want)
	for proj, c := range rootPins {
		demands[proj] = append(demands[proj], c)
	}
	now, unresolved := resolveLock(lset, overlayDir, pantryDir, tgt, order, demands, read, mode == artifact.PinsPublished, rootPins)

	fmt.Fprintf(stdout, "lock: %s · %s · %d pinned, %s · pinned from the %s\n",
		platform, want.Generated, len(want.Pins), lockAge(want.Generated, lockNow()), mode)
	for _, r := range []struct{ name, was, now string }{
		{"pantry", want.Pantry, gitRevOf(pantryDir)},
		{"overlay", want.Overlay, gitRevOf(overlayDir)},
	} {
		if r.was != r.now {
			fmt.Fprintf(stdout, "lock: %s revision differs: %s → %s\n", r.name, r.was, r.now)
		}
	}
	// An unresolved project is not drift — it is an answer nobody got — and
	// it must not be folded into the moved count, or a registry outage would
	// read as a pantry that changed.
	for _, u := range unresolved {
		fmt.Fprintf(stderr, "lock: unresolved: %s\n", u)
	}

	drift := compareLock(want.Pins, now)
	if len(drift) == 0 && len(unresolved) == 0 {
		fmt.Fprintf(stdout, "lock: %d project(s), none moved\n", len(now))
		return 0
	}
	for _, d := range drift {
		fmt.Fprintf(stdout, "  %-34s %s → %s\n", d.project, d.was, d.now)
	}
	if len(drift) > 0 {
		fmt.Fprintf(stdout, "lock: %d of %d moved\n", len(drift), len(want.Pins))
	}
	return 1
}
