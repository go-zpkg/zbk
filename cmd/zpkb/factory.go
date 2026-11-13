package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/artifactpkg"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/overrides"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
	"github.com/go-zpkg/zpkb/versions"
)

// defaultEpoch pins SOURCE_DATE_EPOCH when the environment leaves it unset, so
// re-publishing the same artifact produces byte-identical SBOM/provenance — hence
// identical referrer digests, so a re-push is idempotent instead of piling up
// duplicates. (factory.sh pinned the same value.)
const defaultEpoch = 1700000000

// failTailLines is how much of a failed build's output lands in
// failures-detail.txt: container-job logs are NOT retrievable through the GitHub
// API, so that artifact is the only way to read the real error afterwards.
const failTailLines = 30

// failErrorLines is how many error-looking lines are kept from ANYWHERE in the
// output, alongside the tail.
//
// A tail is the right shape for a build that stops at its error. It is the
// wrong one for `make --jobs N`: the failing command reports, and then every
// other job in flight drains after it, so by the time make gives up the error
// has scrolled far past 30 lines. A kernel build failed for three and a half
// hours and left this in failures-detail.txt:
//
//	AR      fs/btrfs/built-in.a
//	AR      fs/built-in.a
//	make[1]: *** [.../Makefile:2065: .] Error 2
//
// — the top-level "descend into every subdir" rule, naming no cause at all. The
// only way to learn what actually broke was to run the whole thing again.
const failErrorLines = 20

// Seams: everything the factory does that touches the network, a pantry
// checkout or a real compiler, so runFactory is unit-testable end to end.
var (
	factoryOverrides = overrides.Apply
	factoryList      = versions.List
	factoryResolve   = versions.Resolve
	factoryPublish   = publishArtifact
	// factoryPlan settles what a build IS without building it: the resolved
	// version, the resolved closure, and the identity those give it.
	//
	// ⛔ A SEAM OF ITS OWN BECAUSE THE SKIP DEPENDS ON IT. An artifact is
	// addressed by its identity now, so "is this already published?" cannot
	// be answered before the closure is resolved — and asking it of the bare
	// version, as this did while a version was an address, gave the wrong
	// answer every time a recipe had changed and the version had not.
	factoryPlan = func(r *build.Runner, rec *pantry.Recipe, project, constraint string, tgt target.Target) (build.Plan, error) {
		return r.Plan(rec, project, constraint, tgt)
	}
	factoryBuild = func(r *build.Runner, p build.Plan, rec *pantry.Recipe, project string, tgt, host target.Target, out string) (build.Result, error) {
		return r.BuildPlan(p, rec, project, tgt, host, out)
	}
	// factoryPublishedVersion is the newest version of a project the REGISTRY
	// holds for this platform, membership checked — what --test-only tests.
	factoryPublishedVersion = artifact.PickVersionFor
	factoryUpstreamVersions = artifact.VersionsFor
	factoryRemoveAll        = os.RemoveAll
	factoryDownload         = artifact.DownloadArtifact
	factoryHasPlatform      = func(dist, project, ver, osn, arch string) (bool, error) {
		c, err := artifact.NewOCIClient(dist)
		if err != nil {
			return false, err
		}
		return c.HasPlatform(project, ver, osn, arch)
	}
	// factoryPublishedBuilder reads what made the artifact already sitting at a
	// tag. Separate from factoryHasPlatform rather than folded into it,
	// because that one is stubbed in a dozen tests and widening it would make
	// every one of them restate a fact they do not care about.
	factoryPublishedBuilder = func(dist, project, ver, osn, arch string) (string, error) {
		c, err := artifact.NewOCIClient(dist)
		if err != nil {
			return "", err
		}
		_, builder, err := c.ProvenanceOfTag(project, ver, osn, arch)
		return builder, err
	}
)

// staleBuilderNote is the half-sentence appended to a SKIP when the artifact
// already at that tag was made by a DIFFERENT factory from the one running.
//
// ⛔⛔ THE SKIP WAS TRUE AND USELESS. A build's identity is
// {platform, variants, closure, recipe} and deliberately NOT the builder — a
// zpkb release must not re-address every artifact in the registry, which is Nix's
// and Spack's position about their own build tools. The consequence is that a
// zpkb fix which changes the produced BYTES with every input unchanged lands on
// the same tag, finds it occupied, and is skipped. Forever, silently, on every
// nightly run. (go-zpkg/zpkb#416.)
//
// This does not rebuild — that would spend the fleet's whole build capacity on
// every zpkb release, for a change that usually alters no output. It makes the
// skip SAY SO, so a human reading factory logs after a release that is known to
// change output can re-dispatch those projects with `force`. An invisible skip
// becomes a fact somebody can act on, which is the smallest honest fix.
//
// ⛔ AND IT NEVER TURNS A SKIP INTO A FAILURE. The registry may be unreachable,
// the artifact may predate provenance, the statement may not parse: all three are
// "" and all three mean nothing is known, not that anything is wrong. The note
// is empty whenever the comparison cannot be made.
func staleBuilderNote(dist, project, tag, osn, arch string) string {
	published, err := factoryPublishedBuilder(dist, project, tag, osn, arch)
	if err != nil || published == "" {
		return ""
	}
	mine := builderWithVersion()
	if published == mine {
		return ""
	}
	return fmt.Sprintf("\n   ⚠ it was built by %s, and this is %s — `force` to rebuild it (go-zpkg/zpkb#416)",
		published, mine)
}

// runFactory implements `bk factory`: build a set of pantry recipes — expanded
// to their full runtime closure, deps first — and publish every resulting artifact
// to an OCI registry, signed and attested. It is the pure-Go replacement for
// packages/factory.sh, and keeps its contract:
//
//   - each REQUESTED project builds EVERY available upstream version (newest
//     first, optionally capped); a closure-only dependency builds ONE version —
//     the newest its dependents can all use, which is not always the newest;
//   - a (project, tag, platform) already in the registry is SKIPPED, so shared
//     deps build once and successive runs only fill what is missing;
//   - a per-recipe failure is recorded (failures.txt + failures-detail.txt) and
//     never fails the run: the pantry is built progressively.
func runFactory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("factory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lockFile := fs.String("lock", envOr("LOCK", ""),
		"build exactly the versions a `bk lock` file pins, every pin and not just its roots. "+
			"Takes precedence over --recipes and --recipes-file: a lock is the whole set")
	recipes := fs.String("recipes", envOr("RECIPES", ""), `space-separated projects to build (default: --recipes-file). A word may carry its own version constraint after "@" — "cmake.org@=4.4.2" pins that project alone, which is what closing one index gap needs; --versions applies to every requested project at once`)
	recipesFile := fs.String("recipes-file", "recipes.txt", "file listing one project per line (# comments allowed)")
	noClosure := fs.Bool("no-closure", envBool("NO_CLOSURE"), "build ONLY the requested projects, not their dependency closure. For a repair run, where the dependencies are already published and rebuilding them at their newest upstream version starves the targets behind them")
	pantryDir := fs.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout to build from")
	// The factory BUILDS from the pantry alone — this does not change that.
	// It widens the CLOSURE: a dependency only our overlay declares is one a
	// consumer will demand of the registry, so it has to be built, and until
	// now nothing in the factory could see it. `bk closure` has had the flag
	// since the walk it uses was taught about the overlay; the walk the
	// factory runs was left behind.
	overlayDir := fs.String("overlay", envOr("PANTRY_OVERLAY_DIR", ""), "an overlay checkout whose dependencies COUNT toward the closure, as a consumer resolves them. The recipe built is still the pantry's")
	overridesDir := fs.String("overrides", "overrides", `directory of *.patch recipe overrides ("" to skip)`)
	to := fs.String("to", envOr("DIST", "oci://ghcr.io/go-zpkg/packages"), "oci:// registry to publish to")
	platform := fs.String("platform", envOr("PLATFORM", ""), "target os/arch, e.g. linux/x86-64 (required)")
	artifacts := fs.String("artifacts", "dist", "local directory the built artifacts are staged in")
	maxVersions := fs.Int("max-versions", envInt("MAX_VERSIONS"), "cap versions built per requested project, newest first (0 = all)")
	versionSpec := fs.String("versions", envOr("VERSIONS", ""), `only consider versions of the REQUESTED projects that match this pkgx constraint. A BARE version is a RANGE, not an exact match: "2.28.0" means >=2.28.0 within major 2, so an exact version needs "=2.28.0". Also "^3", ">=2.4". Applied before --max-versions. A closure-only dependency is NOT governed by this: it resolves to the newest version every one of its dependents can use`)
	mirrorFrom := fs.String("mirror-from", "", "instead of building, copy each artifact from this upstream pkgx dist (e.g. https://dist.pkgx.dev) and republish it signed + attested — for versions we cannot or need not rebuild, such as ancient glibc")
	noPublish := fs.Bool("no-publish", envBool("NO_PUBLISH"),
		"BUILD and stage each artifact under --artifacts, and push nothing. Not a dry run: the compile, the staging, the packing and the package's own test all happen — only the one irreversible step is skipped. This is what lets a recipe be built TWICE and the two artifacts compared (`zpkb reproduce`) without publishing a second copy of something already published")
	rebuild := fs.Bool("rebuild", envBool("REBUILD"), "publish a build of an ALREADY-PUBLISHED version as the next `_N` rebuild instead of replacing its tag — Homebrew's `rebuild`, Debian's `+bN`. For a recipe fix that changes the binary without changing the upstream version: fftw gained SIMD codelets and went out as the same 3.3.11, so nothing could tell the two apart. NOT folded into --force, which every manual darwin dispatch already sets: a counter minted on every forced run would bump N each time a lane was retried. ⛔ upstream pkgx/libpkgx cannot parse `_N` at all, so a project carrying one is unreadable to an upstream client")
	requireOrigin := fs.Bool("require-origin", false, "with --mirror-from, PROMOTE instead of mirror: refuse any artifact whose source provenance does not prove the host toolchain was unused, and carry that verdict forward instead of restating it as ours. This is how a sovereign seed reaches the production registry — generations 0 and 1 publish only to a throwaway registry, and `bk origin` is the only thing that can tell one of their artifacts from a host-built one")
	libc := fs.String("libc", "", `C library to link against: "zpkx" targets the gnu.org/glibc artifact instead of the build container's`)
	glibc := fs.String("glibc", "", "build and publish the whole closure against this exact glibc, e.g. 2.27.0 (implies --libc=zpkx)")
	bootstrap := fs.Bool("bootstrap", false, "FIRST FILL ONLY on an architecture no registry has: build without the base toolchain in the environment, taking those tools from the host. The base toolchain is a cycle with no entry point (see build.BootstrapToolDeps), so without this nothing can be built first. Artifacts made this way were driven by unpinned host tools: publish them to a throwaway registry, use them to stage the sovereign rootfs, and rebuild everything inside it")
	advisories := fs.String("advisories", envOr("ADVISORIES_DIR", ""), "advisory tree (`<dir>/<project>/advisories.yaml`) to attach as an OpenVEX document beside each artifact's SBOM and provenance, so a rebuild carries the finding that justified it. Validated ONCE before anything is built")
	jobs := fs.Int("jobs", envInt("JOBS"), "parallelism handed to each recipe build (`hw.concurrency`); 0 = one per CPU. Lower it when the target is emulated.")
	pinToDependents := fs.Bool("pin-to-dependents", envBool("PIN_TO_DEPENDENTS"), "hold a REQUESTED project to the constraints its dependents place on it, as a closure-only one already is. For a SEED, where every project is named and none would otherwise be held to anything: gnu.org/glibc asks for gnu.org/gcc 14 and a seed naming gcc built 16.2.0. OFF by default, because naming a project is how you say \"this version, whatever else wants\" — a repair run must not be talked out of it. An explicit project@constraint still wins. It only sees the dependents IN THIS RUN: a batch that does not reach gnu.org/glibc never learns glibc asks gcc for 14, so for a partial seed use `bk closure --build --pins` over the whole order file and pass the words")
	keepBuildTrees := fs.Bool("keep-build-trees", envBool("KEEP_BUILD_TREES"), "leave each PUBLISHED build tree on disk. By default a tree is removed once its artifact is published, because a run of seventy-six keeps all seventy-six otherwise and the s390x seed filled its disk on the fifty-seventh. A FAILED build's tree is always kept: it is the only copy of what went wrong")
	force := fs.Bool("force", envBool("FORCE"), "rebuild and republish even when the artifact is already in the registry — the projects you REQUESTED only, never the dependency closure behind them")
	compress := fs.String("compress", envOr("COMPRESS", "zstd"), "codec for NEW artifacts: zstd or gzip. Already-published artifacts are never rewritten, so gzip stays readable; this only governs what we create")
	signKey := fs.String("sign", "", "sign published artifacts with this go-attest/sign secret key file (else $SIGNING_KEY)")
	zpkx := fs.String("zpkx", "zpkx", "path to the zpkx binary used for the deps env")
	failures := fs.String("failures", "failures.txt", "write the list of failed builds here")
	failuresDetail := fs.String("failures-detail", "failures-detail.txt", "write each failure's error tail here")
	runTests := fs.Bool("test", true, "run each published package's own test: block and RECORD the outcome (never changes the run's result)")
	testsFile := fs.String("tests", "tests.txt", "write one line per package's test outcome here")
	testTimeout := fs.Duration("test-timeout", 5*time.Minute, "give up on one package's test after this long")
	testOnly := fs.Bool("test-only", envBool("TEST_ONLY"), "build NOTHING: run the recorded test for each project's already-published version. What the factory publishes it tests once, and never again — this is how an artifact that stopped working gets noticed")
	sourceMirror := fs.String("source-mirror", envOr("SOURCE_MIRROR", ""), "keep every source archive a build downloads in this registry, addressed by its sha256 (e.g. oci://ghcr.io/go-zpkg). 57% of this pantry builds from tarballs GitHub GENERATES on request rather than stores, so for those it is the first stored artefact they have ever had")
	sourcePinStrict := fs.Bool("source-pin-strict", false, "fail a fetch when the mirror cannot be ASKED what a URL served before, rather than warning and continuing. A mismatch always fails; this is only about an unreadable store, and the two are different facts -- treating them alike is how trust-on-first-use becomes trust-every-time")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *platform == "" {
		fmt.Fprintln(stderr, "usage: bk factory --platform os/arch [--recipes \"p1 p2\"] [--pantry dir] [--to oci://…]")
		return 2
	}
	// ⛔ A GATE THAT GUARDS NOTHING IS WORSE THAN NO GATE, because the operator
	// believes it ran. --require-origin reads the SOURCE artifact's provenance,
	// and without --mirror-from there is no source to read.
	//
	// Refused HERE, beside the other argument checks, and not further down
	// where the run is already under way: an earlier failure for an unrelated
	// reason — a missing pantry, say — would otherwise mask it, and the
	// operator would read the exit code as being about that instead.
	if *requireOrigin && *mirrorFrom == "" {
		fmt.Fprintln(stderr, "factory: --require-origin reads the provenance of the artifact being copied, "+
			"so it needs --mirror-from. On a BUILD the origin is recorded from this run's own inputs and there is nothing to check.")
		return 2
	}
	// ⛔ REFUSED RATHER THAN QUIETLY IGNORED, because both combinations would
	// do something other than what was asked and look like they worked.
	//
	// --mirror-from COPIES an artifact somebody else built; publishing it is the
	// entire operation, so "mirror but do not publish" is a run that downloads
	// and discards.
	//
	// --rebuild asks the registry for the next free `_N` so a NEW tag can be
	// pushed beside an existing one. With nothing pushed, the counter is
	// minted against a registry that will never see the result.
	if *noPublish && *mirrorFrom != "" {
		fmt.Fprintln(stderr, "factory: --no-publish with --mirror-from would download each artifact and discard it. "+
			"Mirroring IS publishing: there is no build here to keep.")
		return 2
	}
	if *noPublish && *rebuild {
		fmt.Fprintln(stderr, "factory: --rebuild asks the registry for the next free `_N` so a new tag can be pushed "+
			"beside the published one. With --no-publish nothing is pushed, so the counter would be minted against a "+
			"registry that never sees the result.")
		return 2
	}
	// Before any work: an operator who asked for a source mirror and cannot have
	// one is entitled to know now, not after a hundred archives have gone
	// unrecorded.
	if *sourceMirror != "" {
		if err := installSourceMirror(*sourceMirror, stderr, *sourcePinStrict); err != nil {
			fmt.Fprintln(stderr, "factory:", err)
			return 1
		}
	}
	osn, arch, ok := splitPlatform(*platform)
	if !ok {
		fmt.Fprintf(stderr, "factory: bad --platform %q (want os/arch)\n", *platform)
		return 2
	}
	// target.Resolve reads ZPKB_TARGET, and needs it set to get the full
	// target (triple included) for the requested platform.
	os.Setenv("ZPKB_TARGET", *platform)
	tgt, err := target.Resolve()
	if err != nil {
		fmt.Fprintln(stderr, "factory:", err)
		return 1
	}

	// --glibc is the whole-stack glibc floor: it only means anything when the
	// build links our own glibc artifact rather than the container's.
	if *glibc != "" && *libc == "" {
		*libc = "zpkx"
	}

	// ⛔ THE ADVISORY TREE IS CHECKED HERE, AS EARLY AS IT CAN BE — before the
	// pantry is read, before the closure walk resolves a single version over
	// the network, and a long way before the first build.
	//
	// `vexReferrer` refuses to publish an artifact whose advisory file does not
	// parse, which is the right answer in the wrong place: a chunk of fifty
	// runs for hours and the fortieth artifact is where that refusal lands. One
	// read of the tree up front makes it a usage error instead of a lost run.
	advisoryCount, err := checkAdvisories(*advisories)
	if err != nil {
		fmt.Fprintln(stderr, "factory:", err)
		return 1
	}
	if advisoryCount > 0 {
		fmt.Fprintf(stdout, "advisories: %d project(s) with records, from %s\n", advisoryCount, *advisories)
	}

	kp, err := factorySigningKey(*signKey)
	if err != nil {
		fmt.Fprintln(stderr, "factory:", err)
		return 1
	}
	fmt.Fprintln(stdout, "signing:", map[bool]string{true: "enabled", false: "disabled (no key)"}[kp != nil])

	// Local recipe overrides: candidate fixes for genuine upstream-recipe bugs,
	// applied to the pantry before the closure is computed so we validate them
	// here before proposing them upstream.
	var skippedOverrides map[string][]string
	if *overridesDir != "" {
		ores, err := factoryOverrides(overrides.Options{
			Dir:  *overridesDir,
			Root: *pantryDir,
			Log:  func(s string) { fmt.Fprintln(stdout, s) },
			Warn: func(s string) { fmt.Fprintln(stderr, s) },
		})
		if err != nil {
			fmt.Fprintln(stderr, "factory:", err)
			return 1
		}
		skippedOverrides = ores.SkippedProjects
	}

	// The LOGICAL overrides from the same directory. Unlike the patches above
	// they change nothing on disk: they are applied to each recipe's document
	// as it is read, so package.yml keeps its comments and a re-run needs no
	// fresh clone.
	logicalSet, err := logical.LoadDir(*overridesDir)
	if err != nil {
		fmt.Fprintln(stderr, "factory:", err)
		return 1
	}
	if n := len(logicalSet.Projects()); n > 0 {
		fmt.Fprintf(stdout, "%d logical override(s), applied as each recipe is read\n", n)
	}

	// The base toolchain pins perl for the XS-bearing tools inside it. If one of
	// those recipes has moved, every autotools recipe that generates a man page
	// or an info manual will die at install time on a module it cannot load —
	// and the message names a C file, not a pin, so the cause is not obvious
	// from any one failure. Say it once here, where it is one line instead of
	// forty. Reported, not refused: whether a mismatched toolchain should stop a
	// run is the same question as go-zpkg/packages#147 asks of a mirror.
	for _, e := range build.CheckToolchainPerl(logicalSet, *pantryDir) {
		fmt.Fprintln(stderr, "factory: toolchain:", e)
	}

	want, err := factoryWant(*recipes, *recipesFile, *lockFile)
	if err != nil {
		fmt.Fprintln(stderr, "factory:", err)
		return 1
	}
	if len(want) == 0 {
		fmt.Fprintln(stderr, "factory: nothing to build (empty --recipes and --recipes-file)")
		return 1
	}
	requested := map[string]bool{}
	pins := map[string]string{}
	for i, w := range want {
		p, c := splitPin(w)
		want[i] = p
		requested[p] = true
		if c != "" {
			pins[p] = c
		}
	}

	// The closure is what makes a first fill work: build a package's
	// dependencies before it, so a consumer finds them in the registry too. It
	// is the wrong shape for a REPAIR run, where every dependency is already
	// published and only a named version of a named project is missing.
	//
	// Measured: 27 pinned targets expanded to 76 projects, and in 2h40 the run
	// attempted 28 builds — three of them targets, twenty-five of them
	// dependencies it rebuilt at their newest upstream version (zlib, ncurses,
	// sqlite, the whole x.org stack, then python 3.14.7 and, the run before,
	// llvm 22.1.8). It never reached the other 24 targets. A closure dep is
	// resolved with the constraint "*", so it is rebuilt whenever upstream has
	// moved, whether or not anything needed that.
	list := want
	var demands map[string][]string
	if !*noClosure {
		list, demands, _ = closureOf(logicalSet, *overlayDir, *pantryDir, tgt, want, func(s string) { fmt.Fprintln(stderr, s) })
	}
	if *mirrorFrom != "" {
		// Mirroring needs no recipe (no build, and the versions come from the
		// upstream dist), so a requested project the closure walk had to drop for
		// want of one is still mirrored.
		list = appendMissing(list, want)
	}
	fmt.Fprintf(stdout, "closure: %d project(s) for %s (from %d requested)\n", len(list), *platform, len(want))
	if *bootstrap {
		// Loud, and in the artefact's own log: these artifacts were driven by
		// whatever tools the host had, and the only record of that is here.
		fmt.Fprintln(stdout, "BOOTSTRAP: no base toolchain in the build environment — "+
			"these artifacts are a SEED, not a release; rebuild them inside the sovereign rootfs")
	}

	zpkxBin := *zpkx
	if abs, err := lookPath(zpkxBin); err == nil {
		zpkxBin = abs
	}
	runner := buildFactory(zpkxBin)
	runner.LibcMode = *libc
	runner.Glibc = *glibc
	runner.Bootstrap = *bootstrap
	// Emulation is why this is reachable at all: on an aarch64 rootfs run
	// through qemu-user, `make --jobs 32` exhausts the emulated address space
	// and bash stops being able to allocate —
	//   /bin/sh: xmalloc: hashlib.c:72: cannot allocate 8192 bytes
	// which reads like a broken recipe and is not one.
	runner.Concurrency = *jobs

	if err := setCodec(*compress); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	f := &factory{
		runner: runner, tgt: tgt, host: target.Host(),
		osn: osn, arch: arch, platform: *platform,
		dist: *to, artifacts: *artifacts, glibc: *glibc,
		force: *force, key: kp, when: factoryTime(),
		mirror:           strings.TrimRight(*mirrorFrom, "/"),
		requireOrigin:    *requireOrigin,
		rebuild:          *rebuild,
		noPublish:        *noPublish,
		want:             strings.TrimSpace(*versionSpec),
		wantPer:          pins,
		demands:          demands,
		pinToDependents:  *pinToDependents,
		keepBuildTrees:   *keepBuildTrees,
		skippedOverrides: skippedOverrides,
		requested:        requested,
		advisories:       *advisories,
		// A mirror run copies an artifact somebody else built and does not
		// install it here, so there is nothing to test — asking would
		// report "not run" for every package and say nothing.
		// --test-only is a request to test, so it turns testing on rather
		// than silently doing nothing when --test=false is also passed.
		runTests:    (*runTests || *testOnly) && *mirrorFrom == "",
		testOnly:    *testOnly && *mirrorFrom == "",
		testTimeout: *testTimeout,
		testCounts:  map[testState]int{},
		stdout:      stdout, stderr: stderr,
	}
	if f.mirror != "" {
		setUpstreamDist(f.mirror)
		fmt.Fprintf(stdout, "mirror: copying artifacts from %s (no build)\n", f.mirror)
	}

	for _, proj := range list {
		if f.mirror != "" {
			vers, err := f.mirrorVersionsFor(proj, requested[proj], *maxVersions)
			if err != nil {
				f.fail(proj, "", "versions", err)
				continue
			}
			for _, v := range vers {
				f.mirrorOne(proj, v)
			}
			continue
		}
		rec, recDir, err := recipefile.LoadBuildRecipe(logicalSet, *overlayDir, *pantryDir, proj)
		switch {
		case errors.Is(err, recipefile.ErrNoRecipe):
			// A pantry need not be complete: the closure walk names projects
			// that resolve from upstream and have no recipe here.
			fmt.Fprintf(stdout, "SKIP %s (no recipe)\n", proj)
			continue
		case err != nil:
			// A recipe that exists and does not parse is a failure worth
			// recording, not a gap worth skipping.
			f.fail(proj, "", "recipe", err)
			continue
		}
		// `platforms:` was parsed and consulted by nobody, so a darwin run
		// attempted every linux-only recipe and collected the failures. Of the
		// 81 recipes whose platforms: excludes darwin, seven do have a darwin
		// artifact and all seven are MIRRORS — this factory has never built one,
		// so nothing that could succeed is being dropped here.
		if !pantry.Supports(rec, tgt.Platform, tgt.Arch) {
			fmt.Fprintf(stdout, "SKIP %s (recipe does not target %s)\n", proj, *platform)
			f.skipped++
			continue
		}
		vers, err := f.versionsToVisit(rec, proj, requested[proj], *maxVersions)
		if err != nil {
			// In --test-only a version we cannot name is a test that never
			// ran, not a build that failed: nothing was going to be built.
			if f.testOnly {
				f.recordTest(testNotRun, proj, "", err)
				continue
			}
			f.fail(proj, "", "versions", err)
			continue
		}
		runner.RecipeDir = recDir
		for _, v := range vers {
			f.buildOne(rec, proj, v)
		}
	}

	if err := os.WriteFile(*failures, f.failures.Bytes(), 0o644); err != nil {
		fmt.Fprintln(stderr, "factory:", err)
	}
	if err := os.WriteFile(*failuresDetail, f.failuresDetail.Bytes(), 0o644); err != nil {
		fmt.Fprintln(stderr, "factory:", err)
	}
	if f.runTests {
		if err := os.WriteFile(*testsFile, f.tests.Bytes(), 0o644); err != nil {
			fmt.Fprintln(stderr, "factory:", err)
		}
	}
	// Once the batch is over the other publishers have finished too, so a
	// repair sticks — which is the whole reason this runs here rather than
	// after each push.
	if n := repairIndexes(f.dist, f.pushed, stdout, stderr); n > 0 {
		fmt.Fprintf(stdout, "=== %d index(es) repaired after a concurrent publisher dropped a platform ===\n", n)
	}
	fmt.Fprintf(stdout, "=== summary (%s): %d built, %d skipped, %d failed ===\n", *platform, f.ok, f.skipped, f.failed)
	f.reportTests(stdout)
	if f.failures.Len() > 0 {
		fmt.Fprint(stdout, "failures:\n", f.failures.String())
	}
	// Per-recipe failures never fail the run: the pantry fills progressively.
	return 0
}

// factory carries one run's configuration and tallies.
type factory struct {
	runner    *build.Runner
	tgt       target.Target
	host      target.Target
	osn       string
	arch      string
	platform  string
	dist      string
	artifacts string
	glibc     string
	force     bool
	key       *sign.Keypair
	when      time.Time
	mirror    string // upstream dist to copy from, "" = build
	// requireOrigin turns `--mirror-from` into a PROMOTION: refuse any artifact
	// whose source provenance does not prove the host toolchain was unused,
	// and carry that verdict into the republished attestation rather than
	// re-stating it as our own.
	requireOrigin bool
	// rebuild mints a `_N` counter when the version being built is already
	// published here, instead of replacing its tag. See rebuild.go.
	rebuild bool
	// noPublish BUILDS and stages the artifact under --artifacts, and pushes
	// nothing.
	//
	// ⛔ IT EXISTS FOR A QUESTION NOTHING COULD ASK BEFORE: do two builds of
	// one recipe produce the same artifact? Answering it means building twice,
	// and every artifact this factory produced until now went straight to the
	// registry — so asking the question meant publishing a second copy of
	// something already published, which is exactly what `--force` is
	// deliberately loud about. The artifact is written to --artifacts either way;
	// this only skips the push.
	//
	// ⛔ NOT A DRY RUN. The compile happens, the tree is staged, the artifact is
	// packed, and the package's own test still runs. What does NOT happen is
	// the one irreversible part. A flag that also skipped the build would be
	// useless for the question it exists for.
	noPublish bool
	want      string // pkgx constraint the requested projects' versions must satisfy, "" = any
	// demands is what the DEPENDENTS of a project asked for, collected by the
	// closure walk. A closure-only dependency is resolved against it instead of
	// against "*", so the factory stops building a version nobody can use.
	demands map[string][]string
	// pinToDependents holds a REQUESTED project to what depends on it, which is
	// what a SEED wants and a repair run does not. See versionsFor.
	pinToDependents bool
	// keepBuildTrees leaves a published build tree on disk. See dropBuildTree.
	keepBuildTrees bool
	// advisories is the advisory tree each published artifact's OpenVEX document
	// is built from, "" = attach none.
	//
	// It is VALIDATED ONCE, before the first build, by checkAdvisories. The
	// alternative is finding a record that does not parse on the fortieth
	// artifact of a run that has been going for hours — `vexReferrer` refuses
	// rather than publishing an artifact whose justification could not be read,
	// which is right at the publish and far too late for the run.
	advisories string
	// wantPer overrides want for one project, from a `project@constraint` word
	// in --recipes. Closing an index gap needs ONE named version of ONE project,
	// and --versions applies to every requested project at once.
	wantPer map[string]string
	// skippedOverrides maps a project onto the overrides that were meant to
	// change its recipe and could not be applied. Building it anyway produces a
	// artifact from a recipe we know is not the one we meant to build.
	skippedOverrides map[string][]string
	// requested is the set of projects the operator NAMED, as opposed to the
	// ones the closure walk added. --force applies only to the first: see
	// forcing.
	requested map[string]bool
	stdout    io.Writer
	stderr    io.Writer

	// runTests records each published package's own test: block. It never
	// changes ok/skipped/failed or the exit status — see testPublished.
	runTests    bool
	testTimeout time.Duration
	// testOnly builds nothing and tests what the registry already holds.
	testOnly bool

	ok, skipped, failed int
	failures            bytes.Buffer
	failuresDetail      bytes.Buffer
	// tests holds one line per package tested, in all four states. Kept
	// apart from failures.txt because a test outcome is not a build outcome
	// and merging them would make "the chunk failed" ambiguous.
	tests      bytes.Buffer
	testCounts map[testState]int

	// pushed is what this run put in the registry, walked once at the end to
	// check no concurrent publisher dropped a platform from an index.
	pushed []published
}

// versionsToVisit is versionsFor, except that --test-only asks the REGISTRY.
//
// The recipe's resolver names the version this factory WOULD build, which is
// the right question for a build and the wrong one for a test: --test-only
// exists to say whether what we PUBLISHED works. The seed's sweep reported
//
//	not-run openssl.org 4.0.3   no artifact here for this platform
//	not-run tcl-lang.org 9.1.0  no artifact here for this platform
//
// for two projects the registry holds perfectly good artifacts of, at other
// versions. A test of a version nobody published is a test of nothing, and
// reporting it as "no artifact here" reads as a gap in the registry when the
// gap was in the question.
//
// artifact.PickVersionFor checks that the version is actually installable for
// this platform, which our registry's tag listing does not imply — it spans
// every platform. Where it falls back to the upstream dist (a project we
// have never published) it cannot check, and buildOne's own publish check
// catches that one step later.
//
// One version, not --max-versions of them: the question is whether the
// artifact a consumer gets works, and that is the newest published one.
func (f *factory) versionsToVisit(rec *pantry.Recipe, proj string, requested bool, max int) ([]string, error) {
	if !f.testOnly {
		return f.versionsFor(rec, proj, requested, max)
	}
	// constraintFor already answers "what is this project held to here" —
	// its `project@constraint` word, else --versions. Empty means unheld,
	// and PickVersionFor spells that "*".
	constraint := f.constraintFor(proj)
	if constraint == "" {
		constraint = "*"
	}
	v, err := factoryPublishedVersion(proj, constraint, f.osn, f.arch)
	if err != nil {
		return nil, err
	}
	return []string{v.Raw}, nil
}

// versionsFor lists the versions to build for a project: every candidate
// (newest first, capped by max) when it was explicitly requested, or the single
// resolved latest for a closure-only dependency. Resolving the dependency's
// version here (rather than letting the build resolve it) is what makes the
// skip-if-published check possible for deps too.
func (f *factory) versionsFor(rec *pantry.Recipe, proj string, requested bool, max int) ([]string, error) {
	if !requested {
		// The newest version its DEPENDENTS can use, not simply the newest.
		//
		// This resolved against "*" and the dependent's own build then asked
		// for something else, one dispatch and one failed build later:
		//
		//	python.org 3.14.7: resolve deps: no version of
		//	bytereef.org/mpdecimal satisfies "2" (available: 1)
		//
		// mpdecimal 4.0.1 was built because it is newest, and python asks for
		// 2. The constraint was in the dep spec the closure walk already read.
		//
		// Filtering the real candidate list rather than intersecting the
		// constraint STRINGS: an interval solver would have to invent a version
		// inside the interval, and nothing guarantees one was ever released.
		if cs := f.demands[proj]; len(cs) > 0 {
			v, err := f.newestSatisfying(rec, proj, cs)
			if err != nil {
				return nil, err
			}
			return []string{v}, nil
		}
		v, _, err := factoryResolve(rec.Versions, "*")
		if err != nil {
			return nil, err
		}
		return []string{v}, nil
	}
	vts, err := factoryList(rec.Versions)
	if err != nil {
		return nil, err
	}
	if len(vts) == 0 {
		return nil, fmt.Errorf("no candidate versions")
	}
	out := make([]string, 0, len(vts))
	for _, vt := range vts {
		out = append(out, vt.Version)
	}
	if out = f.matching(proj, out); len(out) == 0 {
		return nil, fmt.Errorf("no version matches %q", f.constraintFor(proj))
	}
	// --pin-to-dependents: a REQUESTED project is held to what depends on it,
	// the way a closure-only one already is.
	//
	// It is off by default because naming a project is how an operator says
	// "this version, whatever else wants": a repair run closing one index gap
	// must not be talked out of it by a recipe elsewhere in the pantry.
	//
	// A SEED is the other case. There the operator names every project in the
	// order file, so every project is "requested" and none is held to
	// anything — which is how gnu.org/gcc came out at 16.2.0, twenty-five
	// minutes of compiling, while gnu.org/glibc asks for 14. Passing the pins
	// by hand works and is what `bk closure --pins` is for; doing it by hand
	// is also how a batch got listed in the wrong order twice in one day.
	//
	// An explicit `project@constraint` still wins: the operator was specific.
	//
	// IT ONLY SEES THE DEPENDENTS IN THIS RUN. The demands come from the
	// closure walk over the REQUESTED set, so a batch that does not reach
	// gnu.org/glibc never learns that glibc asks gcc for 14 — and a seed
	// dispatched as `gnu.org/gcc info-zip.org/zip kernel.org/linux-headers`
	// with this flag on still built 16.2.0. Measured, after shipping the
	// flag and believing otherwise.
	//
	// So it is a convenience for a run whose closure already contains the
	// dependents, not a substitute for knowing the pantry. `bk closure
	// --build --pins` walks whatever set you give it — the whole order
	// file, for a seed — and emits the words to pass; those are explicit
	// pins and are not subject to this.
	if f.pinToDependents {
		if _, pinned := f.wantPer[proj]; !pinned {
			if cs := f.demands[proj]; len(cs) > 0 {
				kept := satisfyingAll(out, cs)
				if len(kept) == 0 {
					return nil, fmt.Errorf("no version satisfies every dependent: %s (%d candidate(s))",
						strings.Join(cs, " and "), len(out))
				}
				if n := len(out) - len(kept); n > 0 {
					fmt.Fprintf(f.stdout, "versions %s: %d dropped by its dependents (%s)\n",
						proj, n, strings.Join(cs, " and "))
				}
				out = kept
			}
		}
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	fmt.Fprintf(f.stdout, "versions %s: %d to consider (%s)\n", proj, len(out), f.platform)
	return out, nil
}

// buildOne builds and publishes one (project, version), unless the registry
// already has that artifact for this platform.
// forcing reports whether the skip-if-published check should be bypassed for
// this project.
//
// --force means "rebuild what I asked for, even though it is published" — a
// stale artifact refreshed on purpose. It used to mean that for the whole
// dependency closure too, and that is a different and much more expensive
// thing: dispatching 27 projects expanded to 76, and the run spent 2h40
// rebuilding twenty-five published dependencies (zlib, ncurses, sqlite, the
// x.org stack, python 3.14.7) before it had reached four of the targets.
//
// A dependency is in the list so that dependents find it in the registry. If it
// is already there, that job is done.
func (f *factory) forcing(proj string) bool { return f.force && f.requested[proj] }

func (f *factory) buildOne(rec *pantry.Recipe, proj, ver string) {
	// An override that did not apply is not a warning. The recipe about to be
	// built is the UNPATCHED one, and it will fail for whatever the patch
	// existed to fix — or, worse, succeed and publish an artifact missing a
	// correction somebody made on purpose.
	//
	// Measured 2026-09-24: mozilla.org/nss failed two rebuilds on the exact
	// -Werror error its override disables, because that override had stopped
	// applying and said so in one line among 229 "override applied".
	if patches := f.skippedOverrides[proj]; len(patches) > 0 {
		f.fail(proj, ver, "override", fmt.Errorf("%s did not apply, so this would build an unpatched recipe", strings.Join(patches, ", ")))
		return
	}
	// ⛔ THE VERSION-ONLY TAG, AND ONLY FOR --test-only. It is the prefix the
	// builds of this version share, not an address: `HasPlatform` on it
	// answers "is there any artifact of this version here", which is the right
	// question when nothing is being built and the wrong one when something
	// is — see the plan below.
	tag := flavoredTag(proj, ver, f.glibc)
	// --test-only stops here. The override guard above still applies: an
	// override that did not apply changes the recipe, and the test: block is
	// part of the recipe, so a test rendered from an unpatched one is asking
	// a different question than the operator thinks.
	if f.testOnly {
		switch published, err := factoryHasPlatform(f.dist, proj, tag, f.osn, f.arch); {
		case err != nil:
			// NOT treated as "not published and therefore broken". A registry
			// we could not reach has told us nothing, and the whole reason
			// testNotRun exists is that an unobtained answer must not read as
			// a negative one.
			f.recordTest(testNotRun, proj, ver, fmt.Errorf("publish-check: %w", err))
		case !published:
			f.recordTest(testNotRun, proj, ver, errors.New("no artifact here for this platform — nothing to test"))
		default:
			// Nothing was built on this path, so there is no identity to hand
			// over: the store is asked, and refuses if it holds two.
			f.testPublished(rec, proj, ver, "")
		}
		return
	}
	// ⛔⛔ PLAN BEFORE ASKING WHETHER IT IS PUBLISHED. The identity is a
	// function of the resolved closure, so the question "is THIS BUILD in the
	// registry" cannot be asked until the closure exists. Asking it of the
	// version instead — which is what this did while a version was an address
	// — skipped every package whose RECIPE had changed, because the version
	// had not. Nix and Spack both evaluate to a hash before consulting a
	// binary cache, for exactly this.
	//
	// Planning costs the dependency resolution, not a build, and the build
	// below reuses the plan rather than resolving twice.
	plan, err := factoryPlan(f.runner, rec, proj, "="+ver, f.tgt)
	if err != nil {
		f.fail(proj, ver, "plan", err)
		return
	}
	buildTagged := buildTag(proj, plan.Version, f.glibc, plan.Concrete)
	if !f.forcing(proj) {
		switch published, err := factoryHasPlatform(f.dist, proj, buildTagged, f.osn, f.arch); {
		case err != nil:
			// Treat an unreachable registry as "not published" and build: a
			// redundant rebuild is far cheaper than silently skipping the world.
			fmt.Fprintf(f.stderr, "factory: publish-check %s %s: %v\n", proj, buildTagged, err)
		case published:
			fmt.Fprintf(f.stdout, "⏭  SKIP %s %s (%s) — already published%s\n",
				proj, buildTagged, f.platform, staleBuilderNote(f.dist, proj, buildTagged, f.osn, f.arch))
			f.skipped++
			return
		}
	}

	fmt.Fprintf(f.stdout, "::group::build %s %s (%s)\n", proj, ver, f.platform)
	tw := &tailWriter{w: f.stdout, max: failTailLines}
	f.runner.Run = runBashTo(tw, tw)
	res, err := factoryBuild(f.runner, plan, rec, proj, f.tgt, f.host, f.artifacts)
	fmt.Fprintln(f.stdout, "::endgroup::")
	if err != nil {
		f.failDetail(proj, ver, "build", err, tw.tail())
		return
	}
	if res.ArtifactPath == "" {
		f.fail(proj, ver, "package", fmt.Errorf("build produced no artifact"))
		return
	}

	// res.Version is what actually got built (the recipe's resolver may
	// normalise the requested version), and is what the attestations record.
	//
	// ⛔ With --rebuild, a version already published here becomes `_N` rather
	// than replacing the tag it would otherwise overwrite. Computed from the
	// REGISTRY and not from a counter we keep, so two lanes cannot both think
	// they are _1 — and a read failure refuses rather than guesses, because a
	// guessed number is a collision.
	publishVersion := res.Version
	if f.rebuild {
		n, rerr := nextRebuild(proj, res.Version, f.osn, f.arch)
		if rerr != nil {
			f.fail(proj, res.Version, "rebuild", rerr)
			return
		}
		if n > 0 {
			publishVersion = rebuiltVersion(res.Version, n)
			fmt.Fprintf(f.stdout, "rebuild: %s %s is already published for %s — publishing as %s\n",
				proj, res.Version, f.platform, publishVersion)
		}
	}
	// ⛔ THE ARTIFACT IS ALREADY ON DISK HERE. `res.ArtifactPath` is under
	// --artifacts whether or not anything is pushed, which is why --no-publish
	// can stop at this line and still leave something to compare. It is
	// counted as ok and NOT added to f.pushed: nothing was pushed, and a
	// later step that reads f.pushed (the catalogue, the index) must not be
	// told otherwise.
	if f.noPublish {
		fmt.Fprintf(f.stdout, "✅ BUILT %s %s %s — not published (--no-publish): %s\n",
			proj, buildTag(proj, res.Version, f.glibc, res.Concrete), f.platform, res.ArtifactPath)
		f.ok++
		f.testPublished(rec, proj, res.Version, res.SpecHash)
		f.dropBuildTree(proj, res.Version, res.SpecHash)
		return
	}
	tag, desc, err := factoryPublish(publishOptions{
		Dist: f.dist, Project: proj, Version: publishVersion,
		OS: f.osn, Arch: f.arch, Path: res.ArtifactPath,
		Glibc: f.glibc, Key: f.key, Time: f.when,
		Source: res.Source, BuildEnv: res.BuildEnv,
		Advisories: f.advisories,
		// ⛔ STATED, not inferred from an empty BuildEnv. A bootstrap build
		// resolves no artifacts, so its BuildEnv is empty — but so is one for a
		// artifact we only mirrored, and so was every artifact published before
		// the field existed. A promotion gate needs the difference said out
		// loud (go-zpkg/packages#316).
		Origin: provOrigin{Bootstrap: boolParam(f.runner.Bootstrap), Dist: f.dist},
		// What this build IS. It becomes the tag's `-h<hash>` and the
		// manifest's spec annotation, which artifact.VerifySpec checks against
		// each other — so the two cannot be published out of step.
		Concrete: res.Concrete,
	})
	if err != nil {
		f.fail(proj, res.Version, "publish", err)
		return
	}
	// `tag` and not a recomputation: it is what factoryPublish actually
	// pushed under, so a line saying OK cannot name a tag nobody wrote.
	fmt.Fprintf(f.stdout, "✅ OK %s %s %s\n", proj, tag, f.platform)
	f.ok++
	f.pushed = append(f.pushed, published{project: proj, tag: tag, desc: desc})
	// Before dropBuildTree, though the test reads the INSTALLED prefix and
	// not the tree: if a test ever does reach for a source file, failing
	// with it present is a legible failure and failing with it deleted is a
	// puzzle.
	f.testPublished(rec, proj, res.Version, res.SpecHash)
	f.dropBuildTree(proj, res.Version, res.SpecHash)
}

// dropBuildTree removes a build tree once its artifact is PUBLISHED.
//
// The Runner clears a tree at the start of that project's own build, which is
// enough for one build and nothing for a run of seventy-six. The s390x seed
// filled its disk on the fifty-seventh:
//
//	kernel.org/linux-headers 7.2.8: fetch: write …/gc_9_2_1_sh_mask.h:
//	no space left on device
//
// — with every earlier tree still sitting there, gcc's among them.
//
// Only on SUCCESS, and that asymmetry is the point: a failed build's tree is
// the only copy of what went wrong, and a factory that swept it away would
// make every failure unreproducible. Publishing is the moment the tree stops
// being the artefact and starts being litter.
//
// Reported, not silent: a removal that fails leaves the disk filling, and the
// next failure would name a different project.
// ⛔ IT NEEDS THE BUILD'S IDENTITY, because `BuildInstall` is derived from
// the install prefix and the install prefix now carries the hash. Removing
// the tree of a DIFFERENT build would be worse than leaving litter: it would
// delete a staged install somebody else is about to publish.
func (f *factory) dropBuildTree(proj, ver, hash string) {
	if f.keepBuildTrees {
		return
	}
	p := config.Compute(proj, ver, hash, f.tgt)
	for _, d := range []string{p.Build, p.BuildInstall} {
		if err := factoryRemoveAll(d); err != nil {
			fmt.Fprintf(f.stderr, "factory: could not remove %s: %v\n", d, err)
		}
	}
}

// mirrorVersionsFor lists the versions to copy for a project: what the UPSTREAM
// dist actually carries for this platform (newest first, capped) for a requested
// project, or just its newest for a closure-only dependency. Upstream's listing
// — not the recipe's tags — is the truth here: only a version upstream published
// an artifact for can be copied.
func (f *factory) mirrorVersionsFor(proj string, requested bool, max int) ([]string, error) {
	vs, err := factoryUpstreamVersions(proj, f.osn, f.arch)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, fmt.Errorf("no upstream artifact for %s/%s", f.osn, f.arch)
	}
	out := make([]string, 0, len(vs))
	here := make(map[string]bool, len(vs)) // what THIS arch actually has
	for i := len(vs) - 1; i >= 0; i-- {    // upstream lists ascending
		out = append(out, vs[i].Raw)
		here[vs[i].Raw] = true
	}
	// A CAP has to be computed from a list every arch job agrees on, or the two
	// jobs mirror DIFFERENT sets and every version only one of them picked ends
	// up alone in its index. Upstream lists differ per platform — circleci.com
	// carries 124 versions for linux/aarch64 and 125 for linux/x86-64 — so
	// `--max-versions 3 --mirror-from …` manufactured exactly the split indexes
	// it was dispatched to repair. Cap on the union across the arches we publish
	// for this OS: same input, same cut, on every runner.
	if max > 0 {
		out = f.unionWithSiblingArches(proj, out)
	}
	// The union decides WHERE to cut, so both arches stop at the same version.
	// It must not decide WHAT to fetch: one the sibling has and this arch does
	// not is not there to mirror, and asking for it fails the entry outright —
	//
	//	gnu.org/gcc 16.2.0 fetch
	//
	// on a darwin/aarch64 that carries sixteen versions but not that one. So
	// the cut runs on the union and the RESULT is intersected back with what
	// this arch actually has.
	if !requested {
		if p := keepPresent(out[:1], here); len(p) == 1 {
			return p, nil
		}
		return nil, fmt.Errorf("no upstream artifact of %s for %s/%s at the version the arches agree on", proj, f.osn, f.arch)
	}
	if out = f.matching(proj, out); len(out) == 0 {
		return nil, fmt.Errorf("no upstream version matches %q", f.want)
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	if out = keepPresent(out, here); len(out) == 0 {
		return nil, fmt.Errorf("no upstream artifact of %s for %s/%s among the versions the arches agree on", proj, f.osn, f.arch)
	}
	fmt.Fprintf(f.stdout, "versions %s: %d to consider (%s, upstream)\n", proj, len(out), f.platform)
	return out, nil
}

// keepPresent drops the versions this arch's upstream listing does not carry,
// preserving order.
func keepPresent(vers []string, here map[string]bool) []string {
	out := vers[:0:0]
	for _, v := range vers {
		if here[v] {
			out = append(out, v)
		}
	}
	return out
}

// matching keeps only the versions satisfying --versions, and says how many it
// dropped. It exists because "newest N" is the wrong handle for a LINE: our
// registry carries cmake 4.4.2 while 114 pantry recipes pin `cmake.org: ^3`, and
// no value of --max-versions reaches a 3.x from a newest-first listing. The
// constraint grammar is pkgx's own, so `^3`, `~3.31`, `>=2.4` and `=1.2.3` all
// mean here what they mean in a recipe.
// constraintFor is the version constraint in force for one project: its own
// `project@constraint` word if it carried one, else the global --versions.
func (f *factory) constraintFor(proj string) string {
	if w, ok := f.wantPer[proj]; ok {
		return w
	}
	return f.want
}

func (f *factory) matching(proj string, vers []string) []string {
	want := f.constraintFor(proj)
	if want == "" {
		return vers
	}
	// Name WHERE the constraint came from: an operator reading "1 dropped" has
	// to know which knob to turn, and the two are set in different places.
	source := `--versions "` + want + `"`
	if _, pinned := f.wantPer[proj]; pinned {
		source = `the pin "` + proj + "@" + want + `"`
	}
	out := make([]string, 0, len(vers))
	for _, v := range vers {
		if artifact.ParseVer(v).Satisfies(want) {
			out = append(out, v)
		}
	}
	if n := len(vers) - len(out); n > 0 {
		fmt.Fprintf(f.stdout, "versions %s: %d dropped by %s\n", proj, n, source)
	}
	// A BARE version is a caret range, not an exact match: "14" keeps every
	// 14.x, and "2.28.0" keeps 2.29 and 2.33 too. An operator typing a version
	// they read in an error message means THAT version — and finds out
	// otherwise when the run builds a dozen, or fills a disk. Say it while the
	// run is young.
	if len(out) > 1 && isBareVersion(want) {
		fmt.Fprintf(f.stderr, "versions %s: %s is a RANGE and matched %d versions (%s); use %q for exactly one\n",
			proj, source, len(out), strings.Join(out, " "), "="+want)
	}
	return out
}

// isBareVersion reports whether s is a version with no operator — the form
// whose range semantics surprise people.
func isBareVersion(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// mirrorOne copies one upstream artifact into our registry, republished with our
// own SBOM, provenance and signature (and, for glibc, its min-kernel floor).
func (f *factory) mirrorOne(proj, ver string) {
	tag := flavoredTag(proj, ver, f.glibc)
	if !f.forcing(proj) {
		switch published, err := factoryHasPlatform(f.dist, proj, tag, f.osn, f.arch); {
		case err != nil:
			fmt.Fprintf(f.stderr, "factory: publish-check %s %s: %v\n", proj, tag, err)
		case published:
			fmt.Fprintf(f.stdout, "⏭  SKIP %s %s (%s) — already published\n", proj, tag, f.platform)
			f.skipped++
			return
		}
	}
	// ⛔ BEFORE THE DOWNLOAD, so an artifact that may not be promoted is not even
	// fetched. The check is about the SOURCE's provenance, and nothing about
	// having the tarball in hand makes it more promotable.
	srcOrigin := provOrigin{Dist: f.dist}
	if f.requireOrigin {
		o, oerr := f.promotableOrigin(proj, tag)
		if oerr != nil {
			f.fail(proj, ver, "origin", oerr)
			return
		}
		// Carried, not restated. The facts belong to the BUILD, and copying
		// an artefact between registries does not change what built it —
		// whereas re-stating them as ours would launder a verdict we did not
		// make.
		srcOrigin = o
	}
	data, ext, err := factoryDownload(proj, ver, f.osn, f.arch)
	if err != nil {
		f.fail(proj, ver, "fetch", err)
		return
	}
	// Stage it in the same pkgx dist layout a build writes, so the Pages mirror
	// picks a mirrored artifact up exactly like a built one.
	dir := filepath.Join(f.artifacts, filepath.FromSlash(proj), f.osn, f.arch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.fail(proj, ver, "fetch", err)
		return
	}
	path := filepath.Join(dir, "v"+ver+ext)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		f.fail(proj, ver, "fetch", err)
		return
	}
	// A mirror is never unpacked, so fixup's relocatability guards never run on
	// it. Read them off the staged tarball instead — it costs one decompression
	// and says, at publish time, what would otherwise surface weeks later as a
	// third package's dyld error. See go-zpkg/packages#147.
	if f.osn == "darwin" {
		switch checked, problems, aerr := auditMirroredArtifact(path, ext, proj, ver); {
		case aerr != nil:
			fmt.Fprintf(f.stderr, "⚠️  %s %s (%s): not audited: %v\n", proj, ver, f.platform, aerr)
		case len(problems) > 0:
			fmt.Fprintf(f.stderr, "⚠️  NOT RELOCATABLE %s %s (%s): %d of %d Mach-O\n",
				proj, ver, f.platform, len(problems), checked)
			for i, pr := range problems {
				if i == 3 {
					fmt.Fprintf(f.stderr, "      … and %d more\n", len(problems)-3)
					break
				}
				fmt.Fprintf(f.stderr, "      %v\n", pr)
			}
		}
	}
	// A MIRRORED artifact gets the document too. We did not build it, but we
	// are the one republishing it signed — and "what is known about this
	// package" is not a property of who compiled it.
	tag, desc, err := factoryPublish(publishOptions{
		Dist: f.dist, Project: proj, Version: ver,
		OS: f.osn, Arch: f.arch, Path: path,
		Glibc: f.glibc, Key: f.key, Time: f.when,
		Advisories: f.advisories,
		// A plain mirror states only where it was PUT, never a bootstrap
		// verdict: somebody else compiled it and we have no idea with what.
		// Leaving Bootstrap empty is what keeps it out of a promotion gate.
		// Under --require-origin this carries the SOURCE's verdict instead.
		Origin: srcOrigin,
	})
	if err != nil {
		f.fail(proj, ver, "publish", err)
		return
	}
	fmt.Fprintf(f.stdout, "✅ MIRRORED %s %s %s (%d KiB)\n", proj, tag, f.platform, len(data)/1024)
	f.ok++
	f.pushed = append(f.pushed, published{project: proj, tag: tag, desc: desc})
}

// appendMissing returns list plus every want not already in it, order preserved.
func appendMissing(list, want []string) []string {
	have := map[string]bool{}
	for _, p := range list {
		have[p] = true
	}
	for _, p := range want {
		if !have[p] {
			have[p] = true
			list = append(list, p)
		}
	}
	return list
}

// setUpstreamDist points the artifact package at the dist being mirrored. Upstream
// static dists carry no signatures (attestations are OCI referrers), and artifact
// verifies by default, so verification is turned off for the copy unless the
// operator demanded it — mirroring copies bytes, it does not install them, and
// what we publish is re-signed with OUR key.
func setUpstreamDist(from string) {
	artifact.DistBase = from
	if _, ok := os.LookupEnv("ZPKG_VERIFY"); !ok {
		os.Setenv("ZPKG_VERIFY", "0")
	}
}

// fail records a failed (project, version) at a stage.
func (f *factory) fail(proj, ver, stage string, err error) {
	f.failDetail(proj, ver, stage, err, err.Error())
}

// failDetail records a failure plus the text a human needs to diagnose it.
func (f *factory) failDetail(proj, ver, stage string, err error, detail string) {
	if ver == "" {
		ver = "latest"
	}
	fmt.Fprintf(f.stdout, "❌ %s FAIL %s %s: %v\n", strings.ToUpper(stage), proj, ver, err)
	fmt.Fprintf(&f.failures, "%s %s %s\n", proj, ver, stage)
	fmt.Fprintf(&f.failuresDetail, "########## %s %s (%s) — %s failed: %v\n%s\n\n", proj, ver, f.platform, stage, err, detail)
	f.failed++
}

// splitPin cuts a requested word into its project and its own version
// constraint: "cmake.org@=4.4.2" is the project cmake.org pinned to exactly
// 4.4.2. Without an "@" the constraint is empty and --versions governs.
//
// This exists because closing an index gap is inherently per-project: the
// worklist says cmake.org needs 4.4.2 and groonga.org needs 16.0.9, and
// --versions applies one constraint to every requested project at once. Without
// it each gap costs its own dispatch, and a batch built with --max-versions 1
// quietly builds whatever upstream released this week instead — which is what
// happened, and why 17 of 18 targets in one run were never touched.
func splitPin(word string) (proj, constraint string) {
	if i := strings.IndexByte(word, '@'); i >= 0 {
		return word[:i], word[i+1:]
	}
	return word, ""
}

// factoryWant is the requested project list: the --recipes words if given, else
// the non-blank, non-comment lines of --recipes-file.
func factoryWant(recipes, file, lock string) ([]string, error) {
	// A LOCK, which is the most specific of the three and therefore first.
	//
	// It expands into the same `project@=version` words --recipes already
	// takes, so a locked run and a free one go through ONE path. A second
	// way of honouring pins would drift from the first, and the drift
	// would be invisible until two builds differed -- which is the exact
	// failure a lock exists to prevent.
	if strings.TrimSpace(lock) != "" {
		d, err := readLock(lock)
		if err != nil {
			return nil, err
		}
		// NO `pins nothing` CHECK HERE ANY MORE, and the reason is worth a
		// paragraph because the check it replaces was a good one.
		//
		// Until artifact v0.38.0 a pin could carry an empty project or an
		// empty version, so this loop skipped it and the count afterwards
		// caught a lock that pinned nothing — building nothing while
		// reporting success is how a run silently stops being locked.
		//
		// v0.38.0 validates both while PARSING: a lock with no `locked`
		// entries is refused, and so is an empty version, by name. The
		// branch here became unreachable, which the 100% coverage gate
		// reported rather than letting it sit.
		//
		// Deleting it does not mean trusting another repository. The
		// contract bk depends on is pinned by TestArtifactRefusesALockThatPinsNothing,
		// which fails if artifact ever relaxes — a test that goes red is
		// worth more than a branch that cannot run.
		out := make([]string, 0, len(d.Pins))
		for _, p := range d.Pins {
			out = append(out, p.Project+"@="+p.Version)
		}
		sort.Strings(out)
		return out, nil
	}
	if strings.TrimSpace(recipes) != "" {
		return strings.Fields(recipes), nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out, nil
}

// factorySigningKey loads the artifact signing key from a file, or — as CI has it
// — straight from $SIGNING_KEY, so no secret is ever staged on disk.
func factorySigningKey(path string) (*sign.Keypair, error) {
	if path != "" {
		return loadSigningKey(path)
	}
	if k := os.Getenv("SIGNING_KEY"); k != "" {
		return sign.LoadSecretKey(k)
	}
	return nil, nil
}

// factoryTime is the attestation timestamp: SOURCE_DATE_EPOCH when set, else
// the factory's pinned epoch (never the wall clock, which would make every
// re-publish a new artifact).
func factoryTime() time.Time {
	if os.Getenv("SOURCE_DATE_EPOCH") == "" {
		return time.Unix(defaultEpoch, 0).UTC()
	}
	return buildTime()
}

// envInt reads a non-negative integer environment variable, 0 if unset/invalid.
// envBool reads a flag's default from the environment, and `FORCE=0` means
// FALSE.
//
// Every one of these read `os.Getenv(k) != ""`, which is the shell convention
// — `[ -n "$X" ]` — and it is wrong the moment anyone writes the value out.
// `FORCE=0` is a non-empty string, so it turned forcing ON. Measured
// 2026-09-29 on the s390x seed's own registry, with everything else held:
//
//	FORCE unset   ⏭  SKIP zlib.net 1.3.2 — already published    0 built, 1 skipped
//	FORCE=0       ✅ OK zlib.net 1.3.2                          1 built, 0 skipped
//
// Four flags shared it — FORCE, NO_CLOSURE, PIN_TO_DEPENDENTS and
// KEEP_BUILD_TREES — and the costs are not symmetric. `FORCE=0` rebuilds a
// registry somebody meant to preserve. `NO_CLOSURE=0` builds ONLY the named
// projects, so a seed silently drops every dependency behind them.
// `KEEP_BUILD_TREES=0` keeps every tree, which is how the s390x disk filled.
//
// go-zpkg/packages' build.yml already guarded FORCE by hand
// (`[ "${inputs.force}" = "0" ] || FORCE=1`), which is the workaround that
// says where the defect is. It belongs here, once, for every caller — and
// `bk factory` run by hand is a caller.
//
// strconv.ParseBool FIRST, so 0/f/F/false/FALSE/False are false and
// 1/t/T/true/TRUE/True are true. Anything else non-empty stays TRUE, because
// that is what it meant yesterday and `FORCE=yes` must not start meaning no.
func envBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return true
}

func envInt(key string) int {
	n, err := strconv.Atoi(os.Getenv(key))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// tailWriter passes a build's output straight through while remembering its
// last max lines, so a failure's error tail can be written to the artifact CI
// leaves behind.
type tailWriter struct {
	// One tailWriter is handed to the shell runner as BOTH stdout and stderr,
	// and mvdan.cc/sh runs a script's commands in goroutines — a pipeline, a
	// backgrounded command, or simply the two streams of one command all reach
	// Write at once. Unsynchronised, the buffer below is re-sliced by one
	// goroutine while another indexes it, and the factory dies mid-run:
	//
	//	panic: runtime error: slice bounds out of range [43:0]
	//	main.(*tailWriter).Write(…) cmd/bk/factory.go:773
	//	mvdan.cc/sh/v3/interp.(*tracer).flush(…)
	//	created by sync.(*WaitGroup).Go in goroutine 1
	//
	// Measured on go-zpkg/packages run 35504607323, darwin/x86-64: grpc.io had
	// finished compiling and the panic took the WHOLE job with it — the two
	// artifacts already built were never published, and the run reported a build
	// failure for a build that had succeeded.
	mu    sync.Mutex
	w     io.Writer
	max   int
	part  []byte
	lines []string
	// errs are the FIRST lines that look like a compiler or make error, kept
	// wherever they appear. First rather than last: under parallelism the first
	// failure is the cause and the ones after it are often its consequences.
	errs []string
}

// errorLine reports whether a line looks like the thing a reader is looking
// for. Deliberately a small set of shapes rather than anything containing
// "error": a build prints "-Werror", "error_handling.c" and "0 errors" without
// having failed, and a tail full of those is no better than no tail.
func errorLine(s string) bool {
	switch {
	case strings.Contains(s, "error:"), // clang/gcc, and cmake's "CMake Error:"
		strings.Contains(s, "Error:"),
		strings.Contains(s, "undefined reference"),
		strings.Contains(s, "No rule to make target"),
		strings.Contains(s, "cannot find -l"),
		strings.Contains(s, "bad interpreter"):
		return true
	}
	// A line whose first characters are `***` is a build tool speaking about
	// itself rather than echoing a command — make, autoconf and gcc's configure
	// all use that prefix for their own diagnostics. Requiring "Error " as well
	// kept make's failures and dropped everyone else's:
	//
	//	*** Configuration aarch64-apple-darwin20.0.0 not supported
	//
	// was the ONLY line in a 151 KB gcc log that named the cause — gcc 14.4.0
	// has no aarch64*-*-darwin* case in gcc/config.gcc — and failures-detail.txt
	// did not have it. What it had was `make[1]: *** [Makefile:4637:
	// configure-gcc] Error 1`, which names the target that failed and nothing
	// about why.
	//
	// The prefix is what keeps this narrow. `***` anywhere in a line also
	// matches a banner or a comment; at the start of one it is a convention.
	if strings.HasPrefix(strings.TrimLeft(s, " \t"), "***") {
		return true
	}
	// make prefixes its own line with the recipe name — `make[2]: *** [path:line:
	// target] Error 2` — so it never starts with ***; the Error keeps it apart
	// from a target whose name contains one.
	return strings.Contains(s, "***") && strings.Contains(s, "Error ")
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// The wrapped writer is inside the lock too: two goroutines writing a build
	// log interleaved mid-line is what the tail is supposed to make readable.
	n, err := t.w.Write(p)
	t.part = append(t.part, p[:n]...)
	for {
		i := bytes.IndexByte(t.part, '\n')
		if i < 0 {
			break
		}
		t.push(string(t.part[:i]))
		t.part = append(t.part[:0], t.part[i+1:]...)
	}
	return n, err
}

// push records one complete line. The caller holds t.mu.
func (t *tailWriter) push(line string) {
	t.lines = append(t.lines, line)
	if len(t.lines) > t.max {
		t.lines = t.lines[len(t.lines)-t.max:]
	}
	if len(t.errs) < failErrorLines && errorLine(line) {
		t.errs = append(t.errs, line)
	}
}

// tail is the remembered output, trailing partial line included — preceded by
// the first error-looking lines when they are not already in it.
//
// Both, not one: the errors say what broke and the tail says where the build
// had got to, and a reader who has neither has to run the build again.
func (t *tailWriter) tail() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	lines := t.lines
	if len(t.part) > 0 {
		lines = append(append([]string{}, lines...), string(t.part))
	}
	body := strings.Join(lines, "\n")
	if len(t.errs) == 0 {
		return body
	}
	// Nothing is gained by repeating errors the tail already shows, which is the
	// common case: a build that stopped at its own error.
	kept := make([]string, 0, len(t.errs))
	for _, e := range t.errs {
		if !strings.Contains(body, e) {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		return body
	}
	return "--- first errors, from earlier in the output ---\n" +
		strings.Join(kept, "\n") +
		"\n--- last " + strconv.Itoa(len(lines)) + " lines ---\n" + body
}

// setCodec maps the --compress flag onto the extension artifactpkg writes with.
// Named codecs rather than extensions on the CLI: "zstd" is what an operator
// knows the format as, ".tar.zst" is how it lands on disk.
func setCodec(name string) error {
	switch name {
	case "gzip", "gz":
		artifactpkg.Codec = artifact.ExtTarGz
	case "zstd", "zst":
		artifactpkg.Codec = artifact.ExtTarZst
	default:
		return fmt.Errorf("unknown --compress %q (gzip or zstd)", name)
	}
	return nil
}

// siblingArches are the architectures the factory publishes for a given OS.
// Capping a mirror needs a platform-independent version list, and this is the
// set to union over.
//
// It is NOT "the arches bk can target" -- target.supportedArches is that, and
// it is wider. This list asks a different question: whose UPSTREAM version
// list do we cap against? s390x is deliberately absent. Upstream publishes no
// s390x artifacts at all, so every entry would cost one fetch per project and
// contribute nothing, and unionWithSiblingArches prints a line per project
// when a list cannot be read. Add it here when there is an upstream list to
// read, not when there is a runner.
var siblingArches = map[string][]string{
	"linux":  {"x86-64", "aarch64"},
	"darwin": {"x86-64", "aarch64"},
}

// unionWithSiblingArches folds in the upstream versions of the OTHER arches of
// this OS, newest first, so a capped mirror cuts the same list everywhere.
//
// A version present only for a sibling arch stays in the list on purpose: this
// job will report that upstream has no artifact for it here, which is a fact worth
// printing, rather than silently choosing a different set than its sibling.
func (f *factory) unionWithSiblingArches(proj string, mine []string) []string {
	seen := map[string]bool{}
	for _, v := range mine {
		seen[v] = true
	}
	all := append([]string{}, mine...)
	for _, arch := range siblingArches[f.osn] {
		if arch == f.arch {
			continue
		}
		vs, err := factoryUpstreamVersions(proj, f.osn, arch)
		if err != nil {
			// Can't reach the sibling list: cap on ours and say so, rather than
			// pretend the cut is coordinated.
			fmt.Fprintf(f.stderr, "versions %s: cannot read the %s/%s list, capping on %s only: %v\n",
				proj, f.osn, arch, f.platform, err)
			continue
		}
		for _, v := range vs {
			if !seen[v.Raw] {
				seen[v.Raw] = true
				all = append(all, v.Raw)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return lessVersionDesc(all[i], all[j]) })
	return all
}

// lessVersionDesc orders versions newest first.
func lessVersionDesc(a, b string) bool { return artifact.ParseVer(b).Satisfies("<" + a) }

// newestSatisfying picks the newest candidate version of proj that satisfies
// EVERY constraint its dependents placed on it.
//
// Every one, not the first: python.org is asked for `>=3<3.12`, `~3.11` and
// `>=3<3.15` by three different dependents, and only a 3.11.x satisfies all
// three. Picking per-dependent would build a version two of them cannot use.
//
// Where no version satisfies them all, the error names the constraints and who
// is left out — `perl.org` is asked for `~5.42` and `~5.44`, which no single
// perl can be, and those are two builds rather than a choice this can make.
func (f *factory) newestSatisfying(rec *pantry.Recipe, proj string, cs []string) (string, error) {
	vts, err := factoryList(rec.Versions)
	if err != nil {
		return "", err
	}
	all := make([]string, 0, len(vts))
	for _, vt := range vts {
		all = append(all, vt.Version)
	}
	if kept := satisfyingAll(all, cs); len(kept) > 0 {
		return kept[0], nil // newest first, as factoryList returns them
	}
	return "", fmt.Errorf("no version of %s satisfies every dependent: %s (%d candidate(s))",
		proj, strings.Join(cs, " and "), len(vts))
}

// satisfyingAll keeps the versions that satisfy EVERY constraint, in the order
// given — newest first, as factoryList returns them.
//
// Every one, not the first: python.org is asked for `>=3<3.12`, `~3.11` and
// `>=3<3.15` by three different dependents, and only a 3.11.x satisfies all
// three. One filter serves both callers, so a requested project and a
// closure-only one cannot come to different answers about the same demands.
func satisfyingAll(vers, cs []string) []string {
	kept := make([]string, 0, len(vers))
	for _, s := range vers {
		v := artifact.ParseVer(s)
		ok := true
		for _, c := range cs {
			if !v.Satisfies(c) {
				ok = false
				break
			}
		}
		if ok {
			kept = append(kept, s)
		}
	}
	return kept
}

// testPublished runs a just-published package's own test: block and RECORDS
// what it said. It cannot fail the run.
//
// That is the shape go-zpkg/bk#246 settled on, and the measurement behind it
// is why: of 12 failures in the first sweep of 120 packages, only two were a
// package that does not work. The rest were a test calling a tool its recipe
// never declared, or wanting a host config file this sandbox has no business
// providing. A gate on that would stop a chunk over `/etc/containers/policy.json`.
//
// So: one line per package, in all four states, in a file of its own. A
// reader can then ask the question a gate would have answered badly — which
// of these is an artifact nobody can run — with the evidence in front of them.
// factoryTestRunner builds the run function a recorded test executes under.
// A seam, so a test of testPublished's four outcomes does not need pkgx on
// the machine — the first version of these tests stubbed testRun instead,
// which this call bypasses, and every case came back "fail" because `pkgx`
// was not on PATH. Including the deadline case, which then passed without
// any deadline being reached.
var factoryTestRunner = runBashLimited

// hash is the identity of the build just produced, and it is passed rather
// than looked up: the factory KNOWS which build it made, and two builds of one
// version are exactly the case a lookup cannot decide. It is empty only on the
// --test-only path, which built nothing and so has to ask the store.
func (f *factory) testPublished(rec *pantry.Recipe, proj, ver, hash string) {
	if !f.runTests {
		return
	}
	fmt.Fprintf(f.stdout, "::group::test %s %s (%s)\n", proj, ver, f.platform)
	tw := &tailWriter{w: f.stdout, max: failTailLines}
	state, err := runRecipeTest(testRequest{
		Recipe: rec, RecipeDir: f.runner.RecipeDir, Project: proj,
		Version: ver, BuildHash: hash, Target: f.tgt, ZpkxBin: f.runner.ZpkxBin,
		Run: factoryTestRunner(f.testTimeout, tw, tw),
	}, tw, tw)
	fmt.Fprintln(f.stdout, "::endgroup::")
	f.recordTest(state, proj, ver, err)
}

// recordTest writes one outcome down, in all four states.
//
// Separate from testPublished because --test-only reaches two of them
// without running anything: a registry that could not be reached and a
// platform with no artifact are both "not run", and neither is a failure.
func (f *factory) recordTest(state testState, proj, ver string, err error) {
	f.testCounts[state]++
	fmt.Fprintf(&f.tests, "%s %s %s %s\n", state, proj, ver, f.platform)
	switch state {
	case testPassed:
		fmt.Fprintf(f.stdout, "🧪 TEST PASS %s %s\n", proj, ver)
	case testNoBlock:
		// Said out loud rather than left silent: 1905 of 1907 recipes carry
		// a test, so the two that do not are worth seeing, and a package
		// nobody checked must not look like one that passed.
		fmt.Fprintf(f.stdout, "🧪 TEST NONE %s %s — the recipe declares no test\n", proj, ver)
	case testFailed:
		fmt.Fprintf(f.stdout, "🧪 TEST FAIL %s %s: %v (recorded, the build stands)\n", proj, ver, err)
	default:
		fmt.Fprintf(f.stdout, "🧪 TEST NOT-RUN %s %s: %v\n", proj, ver, err)
	}
}

// reportTests prints the tallies, and the failures by name.
//
// Printed even when every count is zero, as long as testing was on: a silent
// section reads as "nothing was wrong" and this one has to be able to say
// "nothing was tried".
func (f *factory) reportTests(stdout io.Writer) {
	if !f.runTests {
		return
	}
	fmt.Fprintf(stdout, "=== tests (%s): %d passed, %d failed, %d with no test, %d not run ===\n",
		f.platform, f.testCounts[testPassed], f.testCounts[testFailed],
		f.testCounts[testNoBlock], f.testCounts[testNotRun])
	if f.tests.Len() == 0 {
		return
	}
	for _, line := range strings.Split(strings.TrimRight(f.tests.String(), "\n"), "\n") {
		if strings.HasPrefix(line, string(testFailed)+" ") {
			fmt.Fprintln(stdout, "  "+line)
		}
	}
}
