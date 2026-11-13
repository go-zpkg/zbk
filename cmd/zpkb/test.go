package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/buildscript"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
	"github.com/go-zpkg/zpkb/versions"
	"mvdan.cc/sh/v3/interp"
)

// exitNoTest is returned when the recipe declares no test: block.
//
// It is neither 0 nor 1 on purpose. A package nobody wrote a test for has not
// passed, and it has not failed either, and a caller that cannot tell the
// three apart will eventually report the first as the second. 1905 of the
// pantry's 1907 recipes carry a test block (go-zpkg/bk#162) — the two that do
// not must not come back green.
const exitNoTest = 3

// exitCannotRun is returned when the test never started: an unresolvable
// version, a recipe that will not parse, a sandbox that cannot be made.
//
// It is separate from 1 because the FIRST sweep this command ever ran could
// not tell them apart. Fourteen of forty projects came back "FAIL", and four
// of those had never executed a line of their test block:
//
//	aomedia.googlesource.com/aom  GET …/+refs: 503 Service Unavailable
//	curl.se/ca-certs              no candidate version matched
//
// A 503 is not a broken package, and reporting it as one is the failure mode
// this repository keeps writing down: an answer that could not be obtained
// must not read as a negative one. Wired into the factory — which is what
// go-zpkg/bk#162 is deciding — that conflation would file bugs against
// packages for an outage.
const exitCannotRun = 4

// testRun executes the generated test script; a seam so a test of this file
// does not need pkgx, a registry, or the package installed.
var testRun = runBash

// runTest renders a recipe's test: block and runs it in a fresh sandbox
// against the INSTALLED package.
//
// The field has existed since the recipe type was written and nothing read
// it: `grep -rn '\.Test\b'` found only toolsurface.go, which scans it for tool
// NAMES and never runs a line of it. So every `test:` block in the pantry was
// parsed and discarded, and the answer to "does this package work?" was
// nobody's (go-zpkg/bk#162).
//
// What it costs is not hypothetical. github.com/rcedgar/muscle 5.3 shipped for
// darwin/aarch64 as a binary the kernel kills on sight, and its recipe's first
// test line is `(muscle --version 2>&1 || true) | grep '{{version.raw}}'` — a
// killed process writes nothing, grep finds nothing, and the package's own
// acceptance test catches exactly the defect that reached the registry.
//
// This runs ONE project on request. Wiring it into the factory is a separate
// decision with a cost (some tests pull network, some are slow, and a
// proportion have never run and will be wrong), and the issue lays out the
// shapes; all of them need this first.
func runTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recipe := fs.String("recipe", "", "path to the package.yml recipe (required)")
	version := fs.String("version", "", "exact version to test (default: latest the recipe resolves)")
	zpkx := fs.String("zpkx", "zpkx", "path to the zpkx binary used for the test env")
	sandbox := fs.String("sandbox", "", "directory to run in (default: the computed testbed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if *recipe == "" || len(rest) < 1 {
		fmt.Fprintln(stderr, "usage: bk test --recipe <package.yml> [--version v] <project>")
		return 2
	}
	project := rest[0]

	// By extension, so an HCL recipe can be tested as well as built.
	rec, err := recipefile.LoadFile(*recipe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitCannotRun
	}
	tgt, err := target.Resolve()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitCannotRun
	}
	// Absolute, for the same reason runBuild does it: the script runs under a
	// sanitized PATH of /usr/bin:/bin:/usr/sbin:/sbin, which excludes the two
	// directories pkgx is normally installed into.
	zpkxBin := *zpkx
	if abs, err := lookPath(zpkxBin); err == nil {
		zpkxBin = abs
	}

	state, _ := runRecipeTest(testRequest{
		Recipe: rec, RecipeDir: filepath.Dir(*recipe), Project: project,
		Version: *version, Target: tgt, Sandbox: *sandbox, ZpkxBin: zpkxBin,
	}, stdout, stderr)
	return state.exit()
}

// testState is what a run of a recipe's test came to.
//
// Four, not two, and named rather than numbered so a caller inside the
// process does not decode an exit status to find out which. See
// exitCannotRun for what the fourth cost before it existed.
type testState string

const (
	testPassed  testState = "pass"
	testFailed  testState = "fail"
	testNoBlock testState = "no-test"
	testNotRun  testState = "not-run"
)

// exit maps a state to the process exit status `bk test` answers with.
func (s testState) exit() int {
	switch s {
	case testPassed:
		return 0
	case testFailed:
		return 1
	case testNoBlock:
		return exitNoTest
	default:
		return exitCannotRun
	}
}

// testRequest is one package's test, decided by the caller rather than by
// flags, so `bk factory` can ask for it with the recipe it already holds.
type testRequest struct {
	Recipe    *pantry.Recipe
	RecipeDir string // holds the fixtures the test names by bare relative name
	Project   string
	Version   string // exact; empty resolves the latest the recipe offers
	Target    target.Target
	Sandbox   string // empty computes the testbed
	ZpkxBin   string
	// BuildHash is the identity of the build to test, which the install
	// prefix now carries. Empty means "find it": `--test-only` tests an
	// already-published artifact and never ran a build, so it has no identity
	// to pass and the store is asked instead.
	BuildHash string
	// Run executes the generated script; nil uses the package default, which
	// is the same pure-Go interpreter a build runs under.
	Run func(scriptPath string, env []string) error
}

// runRecipeTest renders a recipe's test: block and runs it in a fresh sandbox
// against the INSTALLED package.
//
// The field has existed since the recipe type was written and nothing read
// it: `grep -rn '\.Test\b'` found only toolsurface.go, which scans it for
// tool NAMES and never runs a line of it. So every `test:` block in the
// pantry was parsed and discarded, and the answer to "does this package
// work?" was nobody's (go-zpkg/bk#162).
//
// What it costs is not hypothetical. github.com/rcedgar/muscle 5.3 shipped
// for darwin/aarch64 as a binary the kernel kills on sight, and its recipe's
// first test line is `(muscle --version 2>&1 || true) | grep '{{version.raw}}'`
// — a killed process writes nothing, grep finds nothing, and the package's
// own acceptance test catches exactly the defect that reached the registry.
//
// The error it returns accompanies a state; it is never the whole answer. A
// caller that reads only the error cannot tell testNoBlock from testPassed.
func runRecipeTest(req testRequest, stdout, stderr io.Writer) (testState, error) {
	// Asked BEFORE resolving a version or touching the disk: "there is nothing
	// to run" is an answer about the recipe, and making the caller wait for a
	// version resolution to hear it would report a network fault as a missing
	// test.
	if req.Recipe.Test == nil {
		fmt.Fprintf(stdout, "%s declares no test: block — nothing was run\n", req.Project)
		return testNoBlock, nil
	}
	constraint := "*"
	if req.Version != "" {
		constraint = "=" + req.Version
	}
	ver, tag, err := versions.Resolve(req.Recipe.Versions, constraint)
	if err != nil {
		fmt.Fprintln(stderr, "error: resolve version:", err)
		return testNotRun, err
	}

	// ⛔ THE TEST RUNS AGAINST A PARTICULAR BUILD, so it has to name which.
	// `{{prefix}}` below is paths.Install, and the install prefix carries the
	// build's hash — a test pointed at the wrong one would pass or fail about
	// a package nobody asked about.
	hash := req.BuildHash
	if hash == "" {
		p, ok := artifact.ResolveBuild(config.ZpkgDir(), req.Project, artifact.Ver{Raw: ver})
		if !ok {
			err := fmt.Errorf("no installed build of %s %s to test in %s", req.Project, ver, config.ZpkgDir())
			fmt.Fprintln(stderr, "error:", err)
			return testNotRun, err
		}
		b, _ := artifact.ParseStoreDirName(filepath.Base(p))
		hash = b.Variant
	}
	paths := config.Compute(req.Project, ver, hash, req.Target)
	box := req.Sandbox
	if box == "" {
		box = paths.Test
	}
	// Emptied, not merely created. A test block asserts on files it wrote
	// (`test -s aln.afa`), so yesterday's sandbox can carry yesterday's
	// artefact and make today's failed run look green. "Fresh" is the word
	// the schema uses and it has to be true.
	if err := os.RemoveAll(box); err != nil {
		fmt.Fprintln(stderr, "error: clear sandbox:", err)
		return testNotRun, err
	}
	if err := os.MkdirAll(box, 0o755); err != nil {
		fmt.Fprintln(stderr, "error: create sandbox:", err)
		return testNotRun, err
	}
	if err := stageRecipeFiles(req.RecipeDir, box); err != nil {
		fmt.Fprintln(stderr, "error: stage recipe files:", err)
		return testNotRun, err
	}

	// The compiler shims, beside the sandbox for the same reason the script
	// is: the next run empties the sandbox, and a test that lists its working
	// directory must not find our `cc` in it.
	//
	// Made unconditionally rather than only when the test compiles. Deciding
	// needs the rendered script, the render needs the directory, and a few
	// symlinks that nothing looks at cost less than the ordering problem — or
	// than the day the two conditions drift apart.
	shimDir := filepath.Join(filepath.Dir(box), filepath.Base(box)+".shims")
	if err := writeShims(shimDir, true, req.Target.Triple, req.Target.Platform, req.Target.Arch); err != nil {
		// Not fatal. Without the shims a test that calls `cc` by name fails in
		// a scratch rootfs and works everywhere else, which is exactly what
		// happened before they existed; refusing to run the other 1700 tests
		// over it would be the worse trade.
		fmt.Fprintln(stderr, "warning: compiler shims:", err)
		shimDir = ""
	}

	script, err := renderTest(req.Recipe, req.Project, ver, tag, req.Target, paths, box, req.RecipeDir, req.ZpkxBin, shimDir)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return testNotRun, err
	}
	// Beside the sandbox, never inside it: the next run empties the sandbox,
	// and a test that lists its working directory must not find our script
	// there.
	scriptPath := filepath.Join(filepath.Dir(box), filepath.Base(box)+".test.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return testNotRun, err
	}

	run := req.Run
	if run == nil {
		run = testRun
	}
	fmt.Fprintf(stdout, "test %s %s (%s/%s) in %s\n", req.Project, ver, req.Target.Platform, req.Target.Arch, box)
	// A TEST gets GITHUB_TOKEN; a build does not. Two recipes of 1899 ask for
	// it — github.com/spencerkimball/stargazers and
	// github.com/mono0926/LicensePlist — and both ask in their `test:` block,
	// which is what the GitHub API they call needs. No `build:` block in the
	// pantry references it, so SanitizedEnv stopped passing it and this is
	// where the measured need actually is.
	env := build.SanitizedEnv(paths.Home, config.ZpkgDir())
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		env = append(env, "GITHUB_TOKEN="+tok)
	}
	if err := run(scriptPath, env); err != nil {
		// An environment `pkgx` could not assemble is not a test that
		// failed: not one line of the test block ran. Five of the nine
		// failures in the s390x seed's first sweep were this — a test
		// dependency with no artifact for the platform, or a soname pkgx's
		// map does not name — and reporting them as failures files bugs
		// against packages for an incomplete registry.
		var st interp.ExitStatus
		if errors.As(err, &st) && int(st) == buildscript.EnvFailExit {
			// The REASON, not the number. A caller records what comes back
			// here, and the s390x sweep's summary read
			//
			//	🧪 TEST NOT-RUN openssl.org 4.0.2: exit status 69
			//
			// three times — a status nobody can look up, for three
			// different missing test dependencies. The pkgx line naming
			// which one is in the group above, and the line a reader scans
			// has to point at it.
			err = errors.New("the test environment could not be assembled — see the pkgx error above")
			fmt.Fprintf(stderr, "NOT-RUN %s %s: %v\n", req.Project, ver, err)
			return testNotRun, err
		}
		fmt.Fprintf(stderr, "FAIL %s %s: %v\n", req.Project, ver, err)
		return testFailed, err
	}
	fmt.Fprintf(stdout, "PASS %s %s\n", req.Project, ver)
	return testPassed, nil
}

// renderTest turns the recipe's test node into the runnable script.
func renderTest(rec *pantry.Recipe, project, ver, tag string, tgt target.Target,
	paths config.Paths, box, recipeDir, zpkxBin, shimDir string) (string, error) {
	// {{prefix}} is the INSTALLED prefix, not the build's staging directory.
	// That is the whole difference between this and a build: the test reads
	// the package where a consumer would find it, so a file the build made and
	// the artifact omitted is a failure here rather than a surprise later.
	toks := moustache.Prefix(paths.Install)
	toks = append(toks, moustache.Version(ver, "version")...)
	toks = append(toks, moustache.Token{From: "version.tag", To: tag})
	toks = append(toks, moustache.Host(tgt.Arch, tgt.Triple, tgt.Platform, 1)...)
	toks = append(toks,
		moustache.Token{From: "srcroot", To: box},
		moustache.Token{From: "props", To: recipeDir},
		moustache.Token{From: "pkgx.prefix", To: config.ZpkgDir()},
	)
	// {{deps.<project>.prefix}} and .version, for the eleven recipes whose
	// TEST names one. gnu.org/glibc is among them:
	//
	//	gcc -o test-artifact test.c -nostdinc -isystem {{prefix}}/include \
	//	    -isystem {{deps.gnu.org/gcc.prefix}}/lib/gcc/*/…
	//
	// Left verbatim, a moustache reaches the shell and fails somewhere
	// unrecognisable — the hazard build.Runner guards with its own
	// unresolved-{{deps.…}} check.
	//
	// Resolved only when the recipe names one, because resolving costs a
	// registry round-trip per dependency and 1894 of the 1905 recipes with
	// a test block would pay it for nothing — and a 503 would turn a test
	// that was going to pass into one that never ran.
	//
	// The node is scanned BEFORE rendering, which is a superset: a
	// {{deps.…}} behind an `if: darwin` makes linux resolve a dependency it
	// will not use. Rendering first would be exact, and it needs a second
	// Generate whose error cannot happen — the shape has already been
	// accepted — and an unreachable error arm is worse than resolving a
	// handful of times too often.
	//
	// The maps are the recipe's RUNTIME dependencies and its
	// test.dependencies: between them they are what the sandbox installs.
	// Build dependencies are deliberately absent — the test has none of
	// them, so offering their prefixes would render a path to something
	// that is not there.
	if strings.Contains(fmt.Sprint(rec.Test), "{{deps.") {
		dt, _, err := build.DepTokens(rec.Dependencies, testDepMap(rec.Test), tgt, config.ZpkgDir(), resolveTestDep)
		if err != nil {
			return "", fmt.Errorf("resolve test deps: %w", err)
		}
		toks = append(toks, dt...)
	}

	user, err := buildscript.Generate(rec.Test, buildscript.Options{
		Target: tgt, PkgVersion: ver, Tokens: toks,
	})
	if err != nil {
		return "", fmt.Errorf("generate test script: %w", err)
	}
	return buildscript.WrapTest(buildscript.TestWrapOptions{
		UserScript: user,
		// `=ver` so depSpec renders `project@ver`: the exact bytes this run is
		// about. A bare project name would let pkgx pick whatever version the
		// registry likes, and a green line would then be about a different
		// build from the one the operator named.
		Package:  build.DepSpecs(map[string]any{project: "=" + ver}, tgt)[0],
		Deps:     testDepSpecs(rec.Test, tgt),
		Compiler: needsCompiler(user),
		Home:     paths.Home,
		Sandbox:  box,
		ZpkgDir:  config.ZpkgDir(),
		ZpkxBin:  zpkxBin,
		BashPath: "/bin/bash",
		ShimDir:  shimDir,
		Host:     target.Host(),
	}), nil
}

// writeShims is a seam: the shims are symlinks, and the only way they fail to
// be made is a filesystem that refuses — which a test has to stand in for.
var writeShims = buildscript.WriteLibexecFor

// resolveTestDep maps a dependency to a version for the {{deps.…}} tokens.
// A seam: a test of this file must not depend on a registry answering.
var resolveTestDep = pickVersion

// testDepMap reads test.dependencies, which is its own dep map — separate
// from the recipe's runtime and build dependencies, and platform-keyed like
// them. A test node written as a plain string or list has none.
func testDepMap(node any) map[string]any {
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	deps, _ := m["dependencies"].(map[string]any)
	return deps
}

// testDepSpecs renders those dependencies as pkgspecs for the eval.
func testDepSpecs(node any, tgt target.Target) []string {
	deps := testDepMap(node)
	if deps == nil {
		return nil
	}
	return build.DepSpecs(deps, tgt)
}

// dirEntryInfo is os.DirEntry.Info as a seam. It fails only when the entry
// vanished between the listing and the stat — a real race against a pantry
// being updated underneath us, and one no test can provoke by arranging
// files. bk keeps such seams as package vars (build/seams.go does the same
// for os.WriteFile) rather than leaving the branch unexercised.
var dirEntryInfo = func(e os.DirEntry) (os.FileInfo, error) { return e.Info() }

// stageRecipeFiles copies the recipe directory's own files into the sandbox.
//
// Recipes name them by BARE relative name — `cc test.c -lz` in zlib.net,
// `test.pdf` in poppler, `fixture.gif` in giflib, `hello.pro` in qt.io — so a
// sandbox without them makes the test fail on the tool rather than on the
// package. Measured on pantry 2df061b: 357 recipe directories carry a file
// beside their package.yml, and the first sweep this command ever ran reported
//
//   - cc test.c -lz
//     clang: error: no such file or directory: 'test.c'
//
// which reads as a broken package and is a missing fixture.
//
// Regular files only, and no recursion: a subdirectory of a recipe directory
// is ANOTHER PROJECT (zlib.net/minizip has its own package.yml), and copying
// one into the sandbox would put a second package's sources under test.
//
// The RECIPE ITSELF is left out, and the first version of this had it wrong.
// It went in on the reasoning that excluding it "would be a rule about one
// name rather than about the directory" — and then gnu.org/coreutils failed
// the first sweep of the s390x seed:
//
//	touch test-file
//	test "$(ls -1)" = "test-file"
//
// A test that LISTS its working directory sees whatever we put there. The
// same hazard is why the generated script goes beside the sandbox rather
// than in it; the recipe is the thing that DECLARES the fixtures, not one of
// them, and recipefile.Names is where its spellings already live.
//
// The mode travels, because some of these fixtures are meant to be executed
// (agpt.co ships `entrypoint.sh`).
func stageRecipeFiles(recipeDir, sandbox string) error {
	entries, err := os.ReadDir(recipeDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if slices.Contains(recipefile.Names, e.Name()) {
			continue
		}
		info, err := dirEntryInfo(e)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(recipeDir, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(sandbox, e.Name()), data, info.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// compilerNames are the command names a test uses when it compiles. Taken
// from the test surface itself rather than guessed: `bk tools --scope test
// --all` over pantry 2df061b reports cc 193, c++ 38, gcc 13, g++ 7, clang 6
// and clang++ 6 — 260 distinct recipes, not the sum of 263, because three
// call two spellings. Every name here was counted; none is a guess.
var compilerNames = map[string]bool{
	"cc": true, "c++": true, "gcc": true, "g++": true, "clang": true, "clang++": true,
}

// needsCompiler reports whether the rendered test script calls one.
//
// It PARSES, for the reason runTools already gives: a regex asked this
// question of the pantry once and reported `grep` 1231 times by counting the
// word in prose. scriptCommands returns the name in COMMAND position only,
// with shell builtins and script-defined functions subtracted, so a recipe
// whose test merely mentions gcc in a comment does not pull llvm.org in.
func needsCompiler(script string) bool {
	for _, c := range scriptCommands(script) {
		if compilerNames[c] {
			return true
		}
	}
	return false
}
