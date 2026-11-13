package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// runClosure implements `bk closure`: expand a set of pantry projects to their
// transitive runtime-dependency closure for a target platform, printed in
// TOPOLOGICAL order (deps before dependents), one per line. The factory builds a
// package's whole closure into the registry deps-first; a consumer then finds
// every dependency there too. Pure Go (no `go run ./closure` shell-out).
func runClosure(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("closure", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pantryDir := fs.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout dir")
	overridesDir := fs.String("overrides", envOr("OVERRIDES", ""), "directory of *.hcl logical recipe overrides, applied to the pantry's recipes as they are read")
	overlayDir := fs.String("overlay", envOr("PANTRY_OVERLAY_DIR", ""), "an overlay checkout consulted BEFORE the pantry, as the factory consults ZPKG_PANTRY_OVERLAY. Without it this describes a build nobody performs")
	platform := fs.String("platform", envOr("PLATFORM", "linux/x86-64"), "target os/arch")
	withBuild := fs.Bool("build", false, "follow BUILD dependencies as well as runtime ones. The runtime closure is a DAG and is what a consumer needs; adding build dependencies makes it a graph with cycles, and is what FILLING an architecture from nothing actually requires")
	pins := fs.Bool("pins", false, "instead of the order, emit the `project@constraint` words a `bk factory --recipes` dispatch needs, one per line, so the version a REQUESTED project builds is the one its dependents can use. A project whose dependents cannot agree is reported as a comment rather than decided")
	constraints := fs.Bool("constraints", false, "instead of the order, list every project a dependent pins to a version line, and who asks for what. `max_versions=1` builds the newest, and the newest is not always what a dependent can use")
	checkOrderPath := fs.String("check-order", "", "instead of emitting an order, READ one from this file and say what it decided: an edge out of order outside any cycle is a mistake, and the edges it gives up on inside a cycle are the feedback arc set it chose")
	cycles := fs.Bool("cycles", false, "instead of the order, name the dependency CYCLES: one strongly connected component per line. Inside a component the emitted order is a guess, and a wrong guess shows up as a build that fails several steps later")
	implicit := fs.Bool("implicit", false, "also name the soname providers this walk cannot reach — dependencies that exist only in the compiled artefact, which no recipe declares")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	lset, err := logical.LoadDir(*overridesDir)
	if err != nil {
		fmt.Fprintln(stderr, "closure:", err)
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	tgt := target.Target{Platform: osn, Arch: arch}
	roots, _ := closureRoots(fs.Args(), func(s string) { fmt.Fprintln(stderr, s) })
	// A root that is a SET becomes the packages it names. Done here, before
	// anything else looks at the roots, so the walk below and everything it
	// feeds keep working on discrete projects.
	roots = expandSets(lset, *overlayDir, *pantryDir, roots, func(s string) { fmt.Fprintln(stderr, s) })

	// The plain runtime walk keeps going through closureOf, which the factory
	// also calls: one path, so `bk closure` cannot describe an order the
	// factory would not build.
	if !*withBuild && !*constraints && !*implicit && !*pins && !*cycles && *checkOrderPath == "" {
		order, _, _ := closureOf(lset, *overlayDir, *pantryDir, tgt, roots, func(s string) { fmt.Fprintln(stderr, s) })
		if code := reportUnreadableRoots(roots, order, stderr); code != 0 {
			return code
		}
		for _, p := range order {
			fmt.Fprintln(stdout, p)
		}
		return 0
	}
	// --cycles is about BUILD dependencies: the runtime graph is a DAG, and
	// asking it for cycles is asking a question with one possible answer.
	g := newClosureGraph(lset, *pantryDir, tgt, *withBuild || *cycles || *checkOrderPath != "", func(s string) { fmt.Fprintln(stderr, s) })
	g.overlay = *overlayDir
	for _, p := range roots {
		g.visit(p)
	}
	if code := reportUnreadableRoots(roots, g.order, stderr); code != 0 {
		return code
	}
	if *checkOrderPath != "" {
		return checkOrder(g, *checkOrderPath, stdout, stderr)
	}
	comps := g.cycles()
	if *cycles {
		printCycles(comps, stdout)
		return 0
	}
	// Said every time an order is emitted that has one, because the part of it
	// that is arbitrary is not visible in the order itself.
	warnCycles(comps, func(s string) { fmt.Fprintln(stderr, s) })
	printGraph(g, *constraints, *pins, *implicit, stdout)
	return 0
}

// reportUnreadableRoots fails when a project that was ASKED FOR is not in the
// walk. A dependency with no recipe is skipped on purpose — it resolves from
// upstream dist at build time — and for a while a root was skipped by the same
// line, which is a different thing entirely: nobody asked the walk to guess
// whether they meant it.
//
// The cost is that the walk then says nothing and says it successfully. I hit
// this on 2026-09-28 measuring go-zpkg/bk#232: zsh does not word-split an
// unquoted expansion, so all 76 seed projects went in as ONE argument, and the
// walk printed an empty order and exited 0. An empty order is a legal answer to
// a question nobody could ask, and I nearly wrote it down as a finding.
//
// It is checked on the OUTPUT rather than inside either walk, because bk has
// two of them and a check in one is a check the other does not have.
func reportUnreadableRoots(want, order []string, stderr io.Writer) int {
	var lost []string
	for _, p := range want {
		if !slices.Contains(order, p) {
			lost = append(lost, p)
		}
	}
	if len(lost) == 0 {
		return 0
	}
	sort.Strings(lost)
	fmt.Fprintf(stderr, "closure: %d project(s) asked for and not read: %s\n", len(lost), strings.Join(lost, " "))
	return 1
}

// closureOf expands want to its transitive runtime-dependency closure for tgt,
// in topological order (deps before dependents). Shared by `bk closure` and
// `bk factory`, which builds a closure deps-first so that a consumer of any
// package finds every one of its dependencies in the registry too.
//
// It also reports WHAT each dependent asked for. The walk reads the constraint
// off every dep spec and used to drop it on the floor, so the factory resolved
// a closure-only dependency against "*" — the newest — and the dependent's own
// build then asked for something else:
//
//	python.org 3.14.7: resolve deps: no version of bytereef.org/mpdecimal
//	satisfies "2" (available: 1)
//
// The constraint was in the spec the walk had already read.
var closureOf = func(set *logical.Set, overlayDir, pantryDir string, tgt target.Target, want []string, warn func(string)) ([]string, map[string][]string, map[string][]*pantry.Recipe) {
	seen := map[string]bool{}
	var order []string
	demands := map[string][]string{}
	// What the walk READ, handed back rather than re-read. `bk lock` hashes
	// the recipes behind every pin, and a second read would be a second
	// chance to disagree with the walk beside it — as well as an error branch
	// nothing can reach, since a project whose recipes do not load never
	// reaches `order` at all.
	read := map[string][]*pantry.Recipe{}
	var visit func(proj string)
	visit = func(proj string) {
		if seen[proj] {
			return
		}
		seen[proj] = true // mark first: breaks dependency cycles
		recs, err := closureRecipes(set, overlayDir, pantryDir, proj)
		if err != nil {
			// A dependency we have no recipe for can't be built by us — skip it
			// (it resolves from upstream dist at build time), but note it.
			warn(fmt.Sprintf("closure: skip %s: %v", proj, err))
			return
		}
		read[proj] = recs
		for _, rec := range recs {
			for dep, cons := range build.ReduceDeps(rec.Dependencies, tgt) {
				// "*" and "" say nothing, and recording them would make every
				// project look constrained.
				if cons != "" && cons != "*" && !slices.Contains(demands[dep], cons) {
					demands[dep] = append(demands[dep], cons)
				}
			}
			for _, spec := range build.DepSpecs(rec.Dependencies, tgt) {
				visit(depName(spec))
			}
		}
		order = append(order, proj) // post-order → deps precede dependents
	}
	for _, p := range want {
		visit(p)
	}
	for _, cs := range demands {
		sort.Strings(cs)
	}
	return order, demands, read
}

// depName strips the version constraint from a dep spec, in BOTH the forms
// build.DepSpecs renders: "project@1.2" and "project^6"/"project>=6". Keeping
// the operator in the name made the closure look for
// projects/invisible-island.net/ncurses^6/package.yml, miss it, and drop the
// dependency — so readline was built with no ncurses in its environment.
func depName(spec string) string { return build.SpecProject(spec) }

// closureRecipes returns BOTH halves of a project's recipe — the overlay's and
// the pantry's — because both are real and they say different things.
//
// The factory BUILDS from the pantry with the overrides applied; a consumer
// RESOLVES from the overlay. So a dependency declared in only one of them is
// still a dependency of something: the overlay's is what a consumer will demand
// of the registry, the pantry's is what the build itself will need in its
// environment. A closure that reads one half plans a registry the other half
// will find incomplete.
//
// Reading only the pantry is how github.com/besser82/libxcrypt went missing
// from the s390x seed: perl.org declares it in OUR overlay, with a comment
// saying the published perl bottle NEEDs libcrypt.so.1 and glibc dropped it,
// and upstream's perl.org says nothing about it. An overlay-aware read was
// written for that, and `bk closure --build` got it — but closureOf, the walk
// `bk factory` itself runs, kept reading the pantry alone. The order that
// worked was computed by hand with the other tool and handed to the factory as
// an explicit list; a nightly chunked run, which slices recipes.txt, had no
// such list.
//
// Taking the UNION rather than letting the overlay win is deliberate. The
// overlay wins for a CONSUMER, and LoadOverlay is right for what a consumer
// sees, but the closure also decides what a BUILD will be able to resolve, and
// the build reads the pantry. go-zpkg/packages' overlaycheck measured the two
// halves disagreeing for 25 of the 183 projects our overlay carries —
// surrealdb.com asks rust-lang.org for ">=1.60" in the overlay and "~1.95" in
// the patched pantry. Letting the overlay win there would pin rust by a
// constraint the build does not use, and the build would then ask for a
// version nothing had built.
//
// With no overlay directory this is exactly the pantry-only walk it replaces.
func closureRecipes(set *logical.Set, overlayDir, pantryDir, proj string) ([]*pantry.Recipe, error) {
	var recs []*pantry.Recipe
	for _, dir := range []string{overlayDir, pantryDir} {
		if dir == "" {
			continue
		}
		// The logical overrides describe the PANTRY's recipes; our overlay is
		// ours already and has nothing to override.
		load := func() (*pantry.Recipe, error) { return recipefile.Load(dir, proj) }
		if dir == pantryDir {
			load = func() (*pantry.Recipe, error) { return recipefile.LoadOverridden(set, dir, proj) }
		}
		switch r, err := load(); {
		case err == nil:
			recs = append(recs, r)
		case errors.Is(err, recipefile.ErrNoRecipe):
			// Half a project is normal: the overlay carries 183 of several
			// thousand, and a pantry need not be complete either.
		default:
			// A recipe that EXISTS and does not parse is never silently
			// skipped — the walk would plan a build around a recipe it could
			// not read.
			return nil, err
		}
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("%w: %s", recipefile.ErrNoRecipe, proj)
	}
	return recs, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// closureRoots turns the words a caller passed into project names, accepting
// the `project@constraint` form the seed order is written in.
//
// The order file has three readers and only two understood it. readOrder
// (--check-order) cuts at the first `@`, and the factory's splitPin does the
// same for a dispatch — but the closure walk took the whole word as a project
// name, so pinning gnu.org/gawk@~5.3 in seed/order.txt made go-zpkg/packages'
// own gate say
//
//	closure: 2 project(s) asked for and not read: gnu.org/gawk@~5.3 perl.org@~5.44
//
// which since #233 is an error. A form one reader accepts and another reports
// as missing is not a form.
//
// The constraint is DROPPED for the walk, and said out loud rather than
// quietly: a root's version can change its dependencies, so a walk that
// silently ignored the pin would be answering a slightly different question
// than the one asked. Naming them costs one line and stops the next reader
// assuming the walk was version-aware.
// It returns the constraints it stripped as well, keyed by project.
//
// The WALK still cannot use them — that is go-zpkg/bk#140, where a closure
// keyed on the project name collapses two majors into one — but the caller
// that resolves a ROOT can: a root has no dependent, so nothing else will
// ever speak for it. Handing them back is what lets `bk lock` honour
// `nodejs.org@22` instead of writing a file whose `roots` says 22 and whose
// pin says 26.
//
// Returned here rather than re-split by the caller so the `@` rule has one
// definition. Two readings of a pkgspec are two chances to disagree.
func closureRoots(args []string, warn func(string)) ([]string, map[string]string) {
	out := make([]string, 0, len(args))
	constrained := map[string]string{}
	var pinned []string
	for _, a := range args {
		if i := strings.IndexByte(a, '@'); i > 0 {
			pinned = append(pinned, a)
			constrained[a[:i]] = a[i+1:]
			a = a[:i]
		}
		out = append(out, a)
	}
	if len(pinned) > 0 && warn != nil {
		// ⛔ SAY WHICH HALF IS APPLIED. This used to read "a version
		// constraint the walk does not apply", which was true of everything
		// when nothing used the constraints. Now `bk lock` resolves a root
		// by its own, so the same sentence would tell a reader their pin was
		// ignored while the file in front of them honours it — the kind of
		// stale sentence that costs more than silence.
		warn(fmt.Sprintf("closure: %d root(s) carry a version constraint: %s — applied when resolving the root itself, NOT propagated through the walk (go-zpkg/bk#140)",
			len(pinned), strings.Join(pinned, " ")))
	}
	return out, constrained
}
