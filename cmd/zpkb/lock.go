package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// runLock implements `bk lock`: resolve a set (or a list of projects) to the
// exact versions it means TODAY, and write them down.
//
// # WHY A MANIFEST IS NOT ENOUGH, which is not our observation
//
// Guix's manual states it plainly: "to reproduce a profile bit-for-bit,
// manifests alone might not be enough" — the same names resolve differently
// against a different package set, so a manifest needs the channel revisions
// beside it. Spack names the two halves: an environment from `spack.yaml` has
// "the same root specs... may concretize differently", one from `spack.lock`
// has "the same concrete specs".
//
// `members` (go-zpkg/bk#294) gave this factory the abstract half. This is the
// concrete one.
//
// # AND IT MATTERS MORE HERE THAN IN GUIX
//
// A Guix manifest resolves deterministically once the channel revision is
// pinned: the version is in the checkout. A pkgx recipe's `versions:` spec
// asks GitHub for tags AT RESOLVE TIME, so pinning the pantry revision is not
// enough — the same pantry commit resolves `gnu.org/bash` to whatever the
// newest tag is the day you ask. The resolved version has to be written down
// or it is not pinned at all.
//
// # WHAT THIS PINS, AND WHAT IT DOES NOT
//
// It pins the NAMES, the VERSIONS and a per-project SPEC HASH (see specHash),
// and records the pantry and overlay revisions that produced them. The spec
// hash covers the INPUTS — platform, version, parsed recipe, dependencies —
// which is what Nix's derivation hash and Spack's spec hash cover too.
//
// It does not pin the OUTPUT bytes. An artifact digest would, and `artifact` can
// verify a digest but has no exported way to be asked for one; and a lock
// taken before anything is built has no output to name. Saying so is better
// than a lock that quietly guarantees less than a reader assumes.
func runLock(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pantryDir := fs.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout dir")
	overlayDir := fs.String("overlay", envOr("PANTRY_OVERLAY_DIR", ""), "an overlay checkout consulted as the factory consults it")
	overridesDir := fs.String("overrides", envOr("OVERRIDES", ""), "directory of *.hcl logical recipe overrides")
	platform := fs.String("platform", envOr("PLATFORM", "linux/x86-64"), "target os/arch")
	out := fs.String("o", "", "write here instead of stdout")
	check := fs.String("check", "", "re-resolve an existing lock and report what moved, instead of writing one")
	runnable := fs.Bool("runnable", false, "pin the newest version PUBLISHED for -platform, so `pkgx --lock` can run the file, instead of the newest the recipes can build")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// --check takes its roots, its platform and the revisions it expects FROM
	// the file. Naming them again on the command line would let the two
	// disagree, and the check would then be of a different question from the
	// one the file answers.
	if *check != "" {
		// The mode is one more thing the FILE answers — see checkLock.
		// Allowing it here would let the two disagree, and the check would
		// then be of a different question from the one the file answers.
		if *runnable {
			fmt.Fprintf(stderr, "lock --check reads how it was pinned from %s; -runnable on the command line would ask a different question\n", *check)
			return 2
		}
		if fs.NArg() > 0 {
			fmt.Fprintf(stderr, "lock --check reads its roots from %s; %q on the command line would ask a different question\n", *check, fs.Arg(0))
			return 2
		}
		want, err := readLock(*check)
		if err != nil {
			fmt.Fprintln(stderr, "lock:", err)
			return 2
		}
		// A lock that names neither a platform nor a root cannot be checked
		// against anything. Refused rather than defaulted: a default would
		// re-resolve a DIFFERENT question and report "none moved".
		if want.Platform == "" || len(want.Roots) == 0 {
			fmt.Fprintf(stderr, "lock: %s names no %s, so there is nothing to re-resolve\n",
				*check, map[bool]string{true: "platform", false: "roots"}[want.Platform == ""])
			return 2
		}
		return checkLock(want, want.Roots, *pantryDir, *overlayDir, *overridesDir, want.Platform, stdout, stderr)
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "lock: name at least one project or set — a lock of nothing is not an empty lock, it is a mistake")
		return 2
	}
	// Go's flag package stops at the first non-flag argument, so a flag put
	// AFTER a project name is silently a project name. Measured on myself
	// within a minute of writing this command: `bk lock … go-zpkg/base-
	// toolchain -o out.hcl` wrote nothing to out.hcl and printed the lock to
	// stdout instead, because `-o` and `out.hcl` became two more roots.
	//
	// Refused rather than reordered: moving a user's arguments around is a
	// different command from the one they typed, and the day it guesses
	// wrong there is nothing in the output to say so.
	for _, a := range fs.Args() {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(stderr, "lock: %q comes after a project name, and Go's flag parsing "+
				"stops there — it would be read as a project. Put flags before the projects.\n", a)
			return 2
		}
	}
	lset, err := logical.LoadDir(*overridesDir)
	if err != nil {
		fmt.Fprintln(stderr, "lock:", err)
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	tgt := target.Target{Platform: osn, Arch: arch}
	warn := func(s string) { fmt.Fprintln(stderr, s) }

	bare, rootPins := closureRoots(fs.Args(), warn)
	roots := expandSets(lset, *overlayDir, *pantryDir, bare, warn)
	order, demands, read := closureOf(lset, *overlayDir, *pantryDir, tgt, roots, warn)
	if len(order) == 0 {
		fmt.Fprintln(stderr, "lock: the closure is empty — nothing was read, which is a failure and not a clean result")
		return 1
	}

	// A root speaks for itself. Nothing else will: `demands` is built from
	// DEPENDENTS, and a root has none — which is why `bk lock nodejs.org@22`
	// used to write a file whose `roots` said 22 and whose pin said 26.
	for proj, c := range rootPins {
		demands[proj] = append(demands[proj], c)
	}
	pins, unresolved := resolveLock(lset, *overlayDir, *pantryDir, tgt, order, demands, read, *runnable, rootPins)

	doc := lockDoc{
		Version:   lockfileVersion,
		Platform:  *platform,
		Generated: lockNow().UTC().Format(time.RFC3339),
		ZBK:       bkVersion(),
		Roots:     fs.Args(),
		Pantry:    gitRevOf(*pantryDir),
		Overlay:   gitRevOf(*overlayDir),
		Pinned:    lockModeOf(*runnable),
		Pins:      pins,
	}
	b := strings.Builder{}
	b.WriteString(renderLock(doc))

	for _, u := range unresolved {
		fmt.Fprintf(stderr, "lock: unresolved: %s\n", u)
	}
	// SAID AT WRITE TIME, not discovered by whoever tries to use the file.
	// A lock whose pins the platform cannot install is a legitimate build
	// lock and a broken runnable one, and only the person writing it knows
	// which they wanted.
	bad, failedLookups := unpublishedPins(pins, osn, arch)
	reportUnpublished(stderr, pins, bad, failedLookups, *platform, lockModeOf(*runnable), len(unresolved))
	if *out != "" {
		if err := osWriteFile(*out, []byte(b.String()), 0o644); err != nil {
			fmt.Fprintln(stderr, "lock:", err)
			return 1
		}
		fmt.Fprintf(stderr, "lock: %d project(s) pinned → %s\n", len(pins), *out)
	} else {
		fmt.Fprint(stdout, b.String())
	}
	// An unresolved project is a hole in the lock, and a lock with a hole must
	// not read as a success: the next person would commit it.
	if len(unresolved) > 0 {
		return 1
	}
	return 0
}

// lockNow and osWriteFile are seams: a timestamp and a write are the two
// things a test cannot let run free.
var (
	lockNow     = time.Now
	osWriteFile = os.WriteFile
	// recipeLoader is a seam: a project the closure walked but whose recipe
	// the per-project read cannot get is a HOLE in the lock, and the branch
	// that names it is not reachable with a real pantry.
	recipeLoader = recipefile.LoadBuildRecipe
)

// gitRevOf is the checkout's HEAD commit, or a word saying why not.
//
// Not an error: a pantry that is a plain directory — an unpacked tarball, a
// test fixture — is a legitimate thing to lock against, and refusing would
// make the tool unusable in exactly the setting where a lock matters most.
// But the lock must not claim a revision it does not have.
func gitRevOf(dir string) string {
	if dir == "" {
		return "(none)"
	}
	repo, err := gogit.PlainOpenWithOptions(dir, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "(not a git checkout — this lock cannot be replayed from a revision)"
	}
	h, err := repo.Head()
	if err != nil {
		return "(no HEAD)"
	}
	return h.Hash().String()
}
