package build

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/buildscript"
	"github.com/go-zpkg/zpkb/config"
	"github.com/go-zpkg/zpkb/fixup"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/target"
)

// Runner drives a full build. Its side-effecting steps are fields so the whole
// orchestration is testable with stubs; NewRunner wires the real bk packages.
type Runner struct {
	// BuildInstall and Install are the staging and final prefixes the CURRENT
	// build is using, set before Run is called. They are published because the
	// prefix now carries the build's identity hash, which a stubbed Run cannot
	// predict — a real one reads it from the script moustache substituted it
	// into. Written by Build, never read by it.
	BuildInstall string
	Install      string

	PickVersion func(project, constraint string) (string, error)
	// ResolveVersion resolves the MAIN project version from the recipe's own
	// `versions:` spec, so it matches the distributable URL's {{version.raw}}
	// rather than dist's already-built (possibly normalised) bottle list. It
	// also returns the raw upstream git tag the version was resolved from, for
	// the {{version.tag}} moustache used in GitHub release download URLs.
	ResolveVersion func(spec any, constraint string) (version, tag string, err error)
	// Fetch and FetchGit report WHAT they got, not merely that they got it: an
	// archive's SHA-256, a clone's commit. See SourceRef.
	Fetch    func(url, dest string, strip int) (sha256 string, err error)
	FetchGit func(repo, ref, dest string) (commit string, err error)
	// FetchSHA reads the checksum a recipe's `sha:` URL declares for an archive.
	// Nil disables verification — what a test that does not care about it wants;
	// the real runner always sets it.
	FetchSHA    func(shaURL, archiveName string) (string, error)
	Touch       func(dir string) error
	Run         func(scriptPath string, env []string) error
	FixUp       func(fixup.Options) error
	WriteBottle func(installDir, project, version, osn, arch, outDir string) (string, error)
	// ResolveDep, when set, resolves each dependency to a version so the build
	// gets {{deps.<project>.prefix}}/{{deps.<project>.version}} tokens.
	ResolveDep func(project, constraint string) (string, error)
	// ToolInstallable answers whether a BUILD dependency can actually be
	// installed here — its whole closure, not just a version of itself. Only
	// bootstrap asks, and only to decide what to leave to the host; nil falls
	// back to ResolveDep, which is the weaker question.
	//
	// The two differ. perl.org was in the s390x seed registry, so ResolveDep
	// said yes, and the build died installing it: our overlay declares
	// github.com/besser82/libxcrypt as a linux dependency of perl, and that is
	// the project being built.
	ToolInstallable func(project, constraint string) (string, error)
	Concurrency     int
	ZpkgxBin        string
	BashPath        string
	// RecipeDir is the pantry project directory holding the recipe (package.yml)
	// and its sibling files. It is copied into the build tree as `props/` so
	// recipes can reference those files as `props/foo` or via the {{props}}
	// moustache (pkgx's convention). Empty disables the behaviour.
	RecipeDir string
	// LibcMode selects the C library the build links against. "zpkgx" targets
	// the gnu.org/glibc bottle (sovereign FROM-scratch, linux only, C recipes);
	// anything else (default "") keeps the build container's system glibc.
	LibcMode string
	// Glibc pins the exact glibc bottle version to link against in LibcMode
	// "zpkgx" (a chosen HPC floor, e.g. "2.27.0"); empty = newest.
	Glibc string
	// Bootstrap runs the build WITHOUT the base toolchain in its environment,
	// taking those tools from the host instead. It is for the first generation
	// on an architecture no registry has: see BootstrapToolDeps for why nothing
	// can otherwise be built first. It must not be set for an ordinary build --
	// a bottle made this way was driven by tools nobody pinned.
	Bootstrap bool

	// LookPath finds a host binary, for the one case bootstrap has to ask the
	// machine what it already has. nil means exec.LookPath. It is a field so a
	// test can answer without depending on what the machine running it happens
	// to have installed — /usr/bin/sed exists on every developer's laptop and
	// on none of the scratch images.
	LookPath func(string) (string, error)
}

// toolInstallable is the stronger question when the caller can answer it, and
// the weaker one otherwise. A Runner wired with only ResolveDep keeps exactly
// the behaviour it had.
func (r *Runner) toolInstallable() func(project, constraint string) (string, error) {
	if r.ToolInstallable != nil {
		return r.ToolInstallable
	}
	return r.ResolveDep
}

func (r *Runner) lookPath() func(string) (string, error) {
	if r.LookPath != nil {
		return r.LookPath
	}
	return exec.LookPath
}

// SourceRef identifies the bytes a build was actually made from: which of the
// recipe's candidate URLs answered, and the digest of what came back.
//
// A recipe names a URL. A URL is not a source: the list form falls through to a
// mirror when the first host is down, a git tag can be re-cut, and more than
// half of this pantry fetches a tarball GitHub generates on request rather than
// one it stores. Recording the URL alone attests where we knocked, not what we
// were handed.
type SourceRef struct {
	URI    string // the candidate that actually answered
	SHA256 string // lowercase hex, for an archive
	Commit string // for a git source
}

// Result reports what a build produced.
type Result struct {
	Version    string
	Install    string
	ScriptPath string
	BottlePath string
	// Concrete is what this build IS: the platform, the resolved closure and
	// the digest of the canonical recipe. It is published verbatim as the
	// bottle's SpecAnnotation, which is what makes the identity below
	// RECOMPUTABLE by a reader rather than merely asserted.
	Concrete bottle.Concrete
	// SpecHash is Concrete.Hash(), the address: in `Install`, in the registry
	// tag, and checked against the annotation by bottle.VerifySpec.
	//
	// ⛔ IT IS A FUNCTION OF THE INPUTS, NEVER OF THE OUTPUT. It has to be,
	// because it is in `Install` — baked into every binary the build produces
	// — and hashing the result into the result is circular. Nix hashes the
	// derivation and Spack the concrete DAG for the same reason.
	SpecHash string
	// Source is empty for a recipe with no distributable (a few build entirely
	// from their dependencies).
	Source SourceRef
	// BuildEnv is every dependency this build resolved, at the version it
	// actually used — the compiler, its libc, and the tools the recipe
	// invoked. It is what makes a published bottle able to say what compiled
	// it, and the axis along which a rebuild for a toolchain vulnerability
	// differs from the build before it.
	//
	// Empty when the runner has no ResolveDep (a recipe with no
	// dependencies, and the test harness), which is a true statement rather
	// than a missing one.
	BuildEnv []moustache.Dep
}

// Plan is everything a build is decided by, settled before anything is built:
// the version it resolved to, the closure it resolved, and the identity those
// two give it.
//
// ⛔⛔ IT EXISTS SO THE "ALREADY PUBLISHED?" QUESTION CAN BE ASKED ABOUT A
// BUILD. While a bottle was addressed by its version, the factory could ask
// that before resolving anything — and got the wrong answer whenever a recipe
// had changed, because the version had not. Now a bottle is addressed by its
// identity, the identity is a function of the resolved closure, and so the
// question cannot be asked until the closure exists. Nix and Spack both
// evaluate to a hash before consulting a binary cache, for this reason.
//
// Nothing in here touches the install prefix: that is what makes it separable
// at all, and it is also the invariant that keeps the hash a function of the
// INPUTS rather than of the output.
type Plan struct {
	// Version is what the recipe's own `versions:` spec resolved to, and Tag
	// the raw upstream git tag it came from.
	Version string
	Tag     string
	// Concrete is what this build IS, in the form the published bottle
	// carries in its SpecAnnotation and a reader can verify against the tag.
	Concrete bottle.Concrete
	// SpecHash is Concrete.Hash(): the 16 base32 characters a store path and
	// an OCI tag can both hold. ⛔ NOT A SECOND DEFINITION — it is read off
	// Concrete, so the prefix, the tag and the annotation cannot disagree.
	SpecHash string
	// BuildEnv is the closure as resolved: the compiler, its libc and every
	// tool the recipe invoked, at the versions actually used.
	BuildEnv []moustache.Dep

	deps        []string
	toolDeps    []string
	depToks     []moustache.Token
	fromHost    []string
	selfDropped bool
}

// Plan resolves the version and the closure and computes the identity, doing
// none of the work that follows. It touches no directory.
func (r *Runner) Plan(recipe *pantry.Recipe, project, constraint string, tgt target.Target) (Plan, error) {
	var p Plan
	version, tag, err := r.ResolveVersion(recipe.Versions, constraint)
	if err != nil {
		return p, fmt.Errorf("resolve version: %w", err)
	}
	p.Version = version
	// {{version.tag}} = the raw upstream git tag the version resolved from.
	// Some url-form specs have no meaningful tag; fall back to the version so
	// the token still expands rather than staying literal (→ a fetch 404).
	if tag == "" {
		tag = version
	}
	p.Tag = tag

	p.deps = EvalLinkDeps(recipe.Dependencies, tgt)
	bd := buildDeps(recipe)
	if r.Bootstrap {
		_, p.selfDropped = bd[project]
		bd = WithoutSelfDep(project, bd)
		bd, p.fromHost = WithoutUnresolvable(bd, tgt, r.toolInstallable(), func(s string) { logf("%s", s) })
		if p.selfDropped {
			p.fromHost = append(p.fromHost, project)
		}
	}
	p.toolDeps = EvalToolDeps(project, recipe.Dependencies, bd, tgt)
	if r.Bootstrap {
		p.toolDeps = BootstrapToolDeps(bd, tgt)
	}
	if r.ResolveDep != nil {
		dt, resolved, err := DepTokens(recipe.Dependencies, bd, tgt, config.ZpkgDir(), r.ResolveDep)
		if err != nil {
			return p, fmt.Errorf("resolve deps: %w", err)
		}
		p.depToks = dt
		p.BuildEnv = resolved
	}

	// ⛔ DEPENDENCIES ARE IDENTIFIED BY THEIR RESOLVED PREFIX, AND THAT MAKES
	// THE HASH MERKLE FOR FREE. Once a dependency's own prefix carries its
	// own hash, hashing the prefix carries the dependency's whole identity
	// with it — transitively, all the way down. It is the same mechanism as a
	// Nix derivation referencing its inputs by store path.
	//
	// While a dependency is still installed at an unhashed `v<version>`, this
	// degrades to version-level precision for that edge and no further, and
	// it repairs itself as the registry is rebuilt. Said plainly rather than
	// hidden: a hash is only as sharp as what it is taken over.
	c, err := concreteOf(recipe, tgt, p.BuildEnv)
	if err != nil {
		return p, fmt.Errorf("build identity: %w", err)
	}
	p.Concrete = c
	// ⛔ NO GUARD HERE FOR AN EMPTY HASH, ON PURPOSE. Concrete.Hash() is ""
	// only for a spec that records NOTHING, and concreteOf always sets both
	// Platform and Recipe — so a check here is a branch no caller can reach
	// and no test can exercise, which a later reader mistakes for a real
	// case. The invariant is still enforced, one layer down and by something
	// that CAN fire: config.Compute panics on an empty hash, because a prefix
	// without one is the old `v<version>` shape and must never be produced.
	p.SpecHash = c.Hash()
	return p, nil
}

// Build runs the pipeline for project@constraint built for tgt (running on host)
// and, when distOut != "", packages a bottle there.
//
// It plans first. A caller that has already planned — the factory, which has
// to know the identity before it can ask whether this build is published —
// calls BuildPlan instead, so the closure is resolved once.
func (r *Runner) Build(recipe *pantry.Recipe, project, constraint string, tgt, host target.Target, distOut string) (Result, error) {
	p, err := r.Plan(recipe, project, constraint, tgt)
	if err != nil {
		return Result{Version: p.Version}, err
	}
	return r.BuildPlan(p, recipe, project, tgt, host, distOut)
}

// BuildPlan runs the pipeline for a plan already settled.
func (r *Runner) BuildPlan(p Plan, recipe *pantry.Recipe, project string, tgt, host target.Target, distOut string) (Result, error) {
	res := Result{Version: p.Version, BuildEnv: p.BuildEnv, SpecHash: p.SpecHash, Concrete: p.Concrete}
	version, tag := p.Version, p.Tag
	deps, toolDeps, depToks := p.deps, p.toolDeps, p.depToks
	fromHost, selfDropped := p.fromHost, p.selfDropped

	// ⛔ THE HASH GOES IN AS IT IS. It is already Concrete.Hash() — 16 base32
	// characters — and shortening it again here would make the prefix carry
	// a hash of a hash, which is a second definition wearing the first one's
	// name and would not match the tag.
	paths := config.Compute(project, version, p.SpecHash, tgt)
	// ⛔ PUBLISHED FOR THE SCRIPT RUNNER, which is a seam. A real `Run`
	// installs into the prefix the SCRIPT was given — moustache substituted
	// it — but a stubbed one has no script to read it from, and the prefix
	// now carries a hash no caller can predict. Without this a test harness
	// would have to recompute the identity, which is one more place for the
	// definition to drift. Set before Run is called and never read by the
	// pipeline itself.
	r.BuildInstall, r.Install = paths.BuildInstall, paths.Install
	res.Install = paths.Install
	// The two SCRATCH trees, and deliberately not paths.Install.
	//
	// Removing the installed prefix here destroyed the rootfs the build was
	// running in. In the sovereign generation /bin/sh is a symlink to
	// $ZPKG_DIR/gnu.org/bash/v<ver>/bin/bash and /lib/<loader> to glibc's,
	// because $ORIGIN in their RUNPATH has to resolve from the real location
	// — a copy would break it. So `bk factory` building gnu.org/bash at the
	// version /bin/sh points at deleted the shell BEFORE running a line, and
	// every later exec of a `#!/bin/sh` script died with
	//
	//	fork/exec …/configure: no such file or directory
	//
	// naming the script, which exists, rather than the interpreter, which no
	// longer did. Measured on the 78-package s390x generation: gnu.org/bash
	// is built 74th, and ALL FIVE packages after it fail — libtool, cpanmin.us,
	// help2man, gzip — while the 73 before it are untouched. Rebuilding
	// gnu.org/glibc is the same wound one level deeper: it removes the loader
	// every ELF names, after which nothing in the rootfs runs at all. That is
	// why the second generation could not rebuild its own toolchain.
	//
	// Nothing is lost by keeping it: the build installs into BuildInstall
	// (`+brewing`) and the rename at the end already removes paths.Install
	// immediately before replacing it. This one was redundant as well as
	// destructive — and dropping it means a FAILED rebuild no longer destroys
	// a working install, which is worth having on its own.
	for _, d := range []string{paths.Build, paths.BuildInstall} {
		if err := osRemoveAll(d); err != nil {
			return res, err
		}
	}
	if err := osMkdirAll(paths.Build, 0o755); err != nil {
		return res, err
	}
	if err := osMkdirAll(paths.Home, 0o755); err != nil {
		return res, err
	}

	// fetch source
	//
	// A recipe with NO distributable fetches nothing, and that is legitimate:
	// a few generate their whole tree from a script. But the build directory
	// is then EMPTY, and the first step that reaches for a file in it fails
	// with the least informative error the kernel has:
	//
	//	fork/exec …/gnu.org/gzip/v1.15/build/configure: no such file or
	//	directory
	//
	// which reads as "the script is missing" and sends its reader to look at
	// the tarball, the extractor and the shebang — three places that are
	// fine. Measured: that hunt cost six eliminated hypotheses on the s390x
	// second generation before anyone read this branch.
	//
	// So SAY it. One line, on the path where nothing is fetched, naming the
	// consequence rather than the fact.
	if recipe.Distributable == nil {
		logf("recipe declares no distributable: %s stays empty unless a script step fills it", paths.Build)
	}
	if recipe.Distributable != nil {
		srcs, err := sourcesOf(recipe.Distributable, version, tag)
		if err != nil {
			return res, err
		}
		// A list-form distributable lists the canonical source first and fallback
		// mirrors after. Try each in order; a transient failure on one mirror
		// (e.g. a 502 from the primary) then falls through to the next rather than
		// killing an otherwise-buildable recipe. Only fail if every candidate does.
		var fetchErr error
		for i, src := range srcs {
			var got string
			if src.git {
				got, fetchErr = r.FetchGit(src.url, src.ref, paths.Build)
			} else {
				got, fetchErr = r.Fetch(src.url, paths.Build, src.strip)
			}
			if fetchErr == nil {
				// SAY SO. Nothing logged a fetch, and that silence cost a day:
				// four gen1 packages failed at `./configure` with the build
				// directory apparently empty, and the log could not distinguish
				// "the fetch did not happen" from "the fetch happened and put
				// the tree somewhere else" — because a SUCCESSFUL build's log
				// looked exactly the same, which is what finally ruled the
				// inference out. One line per build, naming what answered and
				// how much of it arrived.
				// Counted ONCE: two calls could disagree, and a line that
				// says "1 entries" is a line nobody trusts again.
				n := countEntries(paths.Build)
				logf("fetched %s → %s in %s", src.url, plural(n, "entry", "entries"), paths.Build)
				// Which candidate answered is half the record. A build that fell
				// through to a mirror and one that did not are different builds,
				// and only this says which happened.
				res.Source = SourceRef{URI: src.url}
				if src.git {
					res.Source.Commit = got
				} else {
					res.Source.SHA256 = got
				}
				if err := r.verifyChecksum(src, got); err != nil {
					// NOT a fetch failure, so NOT a reason to try the next mirror.
					// A build that quietly succeeded from a second host after the
					// first served bytes nobody expected is a build that hid the
					// one event this check exists to surface.
					return res, err
				}
				break
			}
			if i < len(srcs)-1 {
				logf("fetch %s failed (%v); trying next mirror", src.url, fetchErr)
			}
		}
		if fetchErr != nil {
			return res, fmt.Errorf("fetch: %w", fetchErr)
		}
		if err := r.Touch(paths.Build); err != nil {
			return res, err
		}
	}

	// Expose the recipe's own directory as `props/` in the build tree — pkgx's
	// convention: a recipe references its sibling files (patches, helper scripts)
	// as `props/foo` or via the {{props}} moustache, where `props` IS the recipe
	// directory (e.g. gnu.org/tar's props/iconv.patch is projects/gnu.org/tar/
	// iconv.patch). Copy the whole recipe dir (package.yml included, harmless).
	propsDir := filepath.Join(paths.Build, "props")
	if r.RecipeDir != "" {
		if _, err := osStat(r.RecipeDir); err == nil {
			if err := copyProps(r.RecipeDir, propsDir); err != nil {
				return res, fmt.Errorf("copy props: %w", err)
			}
		}
	}

	// deps + tokens + script. The RESOLUTION happened before the prefix was
	// chosen — see the identity block above — so only the token assembly is
	// here, where `paths` exists.
	toks := moustache.Prefix(paths.BuildInstall)
	toks = append(toks, moustache.Version(version, "version")...)
	toks = append(toks, moustache.Token{From: "version.tag", To: tag})
	toks = append(toks, moustache.Host(tgt.Arch, tgt.Triple, tgt.Platform, r.concurrency())...)
	toks = append(toks,
		moustache.Token{From: "srcroot", To: paths.Build},
		moustache.Token{From: "props", To: propsDir},
		moustache.Token{From: "pkgx.prefix", To: config.ZpkgDir()},
	)
	toks = append(toks, depToks...)
	// A recipe that build-depends on itself still interpolates its own prefix.
	// Appended AFTER the resolved tokens so it can only fill a gap, never
	// displace a real bottle's prefix: on an architecture where the bottle does
	// exist, nothing was dropped and this produces nothing.
	if selfDropped {
		toks = append(toks, HostPrefixForSelfDep(project, recipe.Provides, r.lookPath())...)
	}
	user, err := buildscript.Generate(recipe.Build, buildscript.Options{Target: tgt, PkgVersion: version, Tokens: toks})
	if err != nil {
		return res, fmt.Errorf("generate: %w", err)
	}
	// A token we dropped a dependency for is left verbatim in the script, and a
	// literal {{deps.…}} reaching the shell fails somewhere unrecognisable.
	// gnu.org/sed builds with {{deps.gnu.org/sed.prefix}}, so dropping ITS
	// self-edge would do exactly that.
	//
	// Checked as a SYMPTOM rather than against a list of the recipes known to
	// do it: the list would be right today and silently short later.
	if r.Bootstrap && strings.Contains(user, "{{deps.") {
		return res, fmt.Errorf("bootstrap: %s builds from a dependency prefix we cannot provide here "+
			"(an unresolved {{deps.…}} remains); it needs a bottle of its own build dependency first", project)
	}
	// Materialise the build-shim helpers (fix-shebangs.ts, …) into a per-build
	// libexec dir alongside the generated script, and prepend it to PATH via
	// BrewkitPath so recipes that exec them (`fix-shebangs.ts bin/*`) resolve.
	libexecDir := paths.Build + ".libexec"
	if err := writeLibexec(libexecDir, r.LibcMode == "zpkgx", tgt.Triple, tgt.Platform, tgt.Arch); err != nil {
		return res, fmt.Errorf("write libexec: %w", err)
	}
	// The map is derived from the root the build really uses and refused when it
	// would not cover the build directories: a no-op map ships the builder's
	// path silently (go-zpkg/bk#387).
	prefixMap, err := buildscript.PrefixMapFor(paths.Root, paths.Home, paths.Src, paths.Build, paths.Test)
	if err != nil {
		return res, err
	}
	script := buildscript.Wrap(buildscript.WrapOptions{
		PrefixMap:  prefixMap,
		UserScript: user, Deps: deps, ToolDeps: toolDeps, Target: tgt, Host: host,
		Home: paths.Home, SrcRoot: paths.Build, ZpkgDir: config.ZpkgDir(), Install: paths.Install, Project: project,
		ZpkgxBin: r.ZpkgxBin, BashPath: r.BashPath, BrewkitPath: libexecDir,
		LibcZpkgx: r.LibcMode == "zpkgx",
		Glibc:     r.Glibc,
		Bootstrap: r.Bootstrap,
	})
	res.ScriptPath = paths.Build + ".sh"
	if err := osWriteFile(res.ScriptPath, []byte(script), 0o755); err != nil {
		return res, err
	}

	// run (sanitized env), stage, fix-up
	if err := r.Run(res.ScriptPath, SanitizedEnv(paths.Home, config.ZpkgDir())); err != nil {
		// Name what the host was asked to supply. Twice now a seed build has
		// died with `exit status 127` -- command not found -- because a tool
		// bootstrap left to the machine was not on the machine either:
		// facebook.com/zstd wanted cmake and ninja, and this Ubuntu had
		// neither. The drop is logged when it happens, but by the time the
		// failure prints, that line is hundreds of lines back and belongs to a
		// different recipe half the time.
		//
		// Attached to EVERY bootstrap failure, not only a 127, because reading
		// the exit code out of this error means matching on its text -- which
		// is how a transient failure quietly becomes a different diagnosis.
		// One extra clause on a failure that is already being read is cheap.
		if len(fromHost) > 0 {
			return res, fmt.Errorf("run: %w; bootstrap took these from the host, and one of them may not be there: %s%s",
				err, strings.Join(fromHost, ", "), buildDirListing(paths.Build, err))
		}
		return res, fmt.Errorf("run: %w%s", err, buildDirListing(paths.Build, err))
	}
	// Stage the completed +brewing tree onto the final versioned prefix. The
	// build and its install step have already succeeded; only this atomic rename
	// remains. If the destination prefix already exists — the same version got
	// built earlier in the dependency closure, or this is a re-run — it is a
	// completed duplicate install and is safe to replace, so remove it first and
	// let the rename proceed rather than fail with "file exists".
	// Move the old one ASIDE rather than delete it, and only drop it once the
	// new one is in place.
	//
	// The same hazard as the up-front removal, one window narrower: between
	// an unlink and a rename the prefix does not exist, and in the sovereign
	// rootfs /bin/sh and /lib/<loader> are symlinks INTO it. Two syscalls is
	// a short window, but a rename that FAILS — a full disk, a crossed
	// filesystem — leaves it open for good, and a rootfs with no shell cannot
	// run the next build or report why.
	//
	// Rename is atomic within a filesystem, so the swap either happens or
	// does not; the old tree goes back if the new one cannot land.
	stale := paths.Install + ".replacing"
	_ = osRemoveAll(stale) // a previous crash could have left one
	haveOld := false
	if _, err := osStat(paths.Install); err == nil {
		if err := osRename(paths.Install, stale); err != nil {
			return res, fmt.Errorf("stage install: move the old prefix aside: %w", err)
		}
		haveOld = true
	}
	if err := osRename(paths.BuildInstall, paths.Install); err != nil {
		if haveOld {
			// Put it back. A build that failed to install must not also have
			// removed what was working.
			_ = osRename(stale, paths.Install)
		}
		return res, fmt.Errorf("stage install: %w", err)
	}
	if haveOld {
		if err := osRemoveAll(stale); err != nil {
			return res, fmt.Errorf("stage install: drop the replaced prefix: %w", err)
		}
	}
	if err := r.FixUp(fixup.Options{Prefix: paths.Install, BuildInstall: paths.BuildInstall, Platform: tgt.Platform, ZpkgDir: config.ZpkgDir()}); err != nil {
		return res, fmt.Errorf("fix-up: %w", err)
	}

	// package
	if distOut != "" {
		p, err := r.WriteBottle(paths.Install, project, version, tgt.Platform, tgt.Arch, distOut)
		if err != nil {
			return res, fmt.Errorf("package: %w", err)
		}
		res.BottlePath = p
	}
	return res, nil
}

func (r *Runner) concurrency() int {
	if r.Concurrency > 0 {
		return r.Concurrency
	}
	return runtime.NumCPU()
}

// BuildDeps is a recipe's build-time dependency map, which lives under the
// free-form `build:` node rather than in a typed field. Exported because a
// recipe's build deps are as capable of naming an unpublishable version as its
// runtime ones — `bk depgaps` counts both.
func BuildDeps(recipe *pantry.Recipe) map[string]any { return buildDeps(recipe) }

func buildDeps(recipe *pantry.Recipe) map[string]any {
	if m, ok := recipe.Build.(map[string]any); ok {
		if bd, ok := m["dependencies"].(map[string]any); ok {
			return bd
		}
	}
	return nil
}

type source struct {
	url   string
	strip int
	git   bool
	ref   string
	// sha is the URL of a file holding the expected checksum, which is how the
	// pantry format already spells this: `sha: ${{url}}.sha256`, pointing at
	// what the upstream publishes NEXT to the tarball. A digest written into
	// the recipe would have to be re-written for every version; this one moves
	// with the URL, which is why openssl.org — the only recipe that had one —
	// spells it this way.
	sha string
	// sha256 is the digest the RECIPE pins, already resolved for the version
	// being built. Empty when the recipe pins nothing.
	sha256 string
}

// oneSource derives a single fetch source from a scalar (string) or map-form
// distributable entry, applying the version moustaches to its fields. Each
// entry keeps its own url / strip-components / git ref.
func oneSource(dist any, version string, toks []moustache.Token) (source, error) {
	switch d := dist.(type) {
	case string:
		return source{url: moustache.Apply(d, toks)}, nil
	case map[string]any:
		s := source{url: moustache.Apply(str(d["url"]), toks)}
		if ref, ok := d["ref"].(string); ok && ref != "" {
			s.git, s.ref = true, moustache.Apply(ref, toks)
		}
		pinned, err := pinnedDigest(d["sha256"], version)
		if err != nil {
			return s, err
		}
		s.sha256 = pinned
		// `${{url}}` in a sha refers to this entry's own url, so the token is
		// added here rather than by the caller: a list-form distributable has a
		// different url per entry, and openssl.org is exactly that shape.
		if sha := str(d["sha"]); sha != "" {
			s.sha = moustache.Apply(sha, append(toks, moustache.Token{From: "url", To: s.url}))
		}
		switch sc := d["strip-components"].(type) {
		case int:
			s.strip = sc
		case string:
			s.strip, _ = strconv.Atoi(sc)
		}
		if s.url == "" {
			return s, fmt.Errorf("distributable has no url")
		}
		return s, nil
	default:
		return source{}, fmt.Errorf("unsupported distributable %T", dist)
	}
}

// sourcesOf derives the ordered candidate fetch sources from a recipe's
// distributable. A scalar or map yields a single candidate; a list yields one
// candidate per entry, in order — the canonical source first and fallback
// mirrors after (e.g. freetype.org ships the savannah tarball plus a mirror) —
// so Build can retry the next mirror when one is unreachable.
func sourcesOf(dist any, version, tag string) ([]source, error) {
	toks := moustache.Version(version, "version")
	// GitHub release download URLs interpolate {{version.tag}} (the raw upstream
	// git tag). Include it so the distributable URL fetches rather than 404ing on
	// a literal, unexpanded token. An empty tag falls back to the version string.
	if tag == "" {
		tag = version
	}
	toks = append(toks, moustache.Token{From: "version.tag", To: tag})
	if lst, ok := dist.([]any); ok {
		if len(lst) == 0 {
			return nil, fmt.Errorf("distributable list is empty")
		}
		srcs := make([]source, 0, len(lst))
		for _, e := range lst {
			s, err := oneSource(e, version, toks)
			if err != nil {
				return nil, err
			}
			srcs = append(srcs, s)
		}
		return srcs, nil
	}
	s, err := oneSource(dist, version, toks)
	if err != nil {
		return nil, err
	}
	return []source{s}, nil
}

// hex64 is a lowercase SHA-256 in hex, which is the only shape a pinned
// digest may take. A pin that is almost a digest is worse than none: it reads
// as a control and compares against nothing real.
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// pinnedDigest resolves the recipe's `sha256:` for the version being built.
//
// ⛔⛔ A PIN BELONGS TO A VERSION, NOT TO A URL. The distributable's url
// interpolates {{version.raw}}, so one entry serves every version the recipe
// can resolve, and a single scalar digest would be right for exactly one of
// them and a lie for the rest. Spack pins on `version(…, sha256=)` and Guix
// on the origin of a specific source for the same reason. So the map form —
// version → digest — is the real shape, and the scalar is allowed only as
// the degenerate case of a recipe that resolves one version.
//
// ⛔ AND A RECIPE THAT PINS IS FAIL-CLOSED. If `sha256:` is present and the
// version being built has no entry, the build is REFUSED rather than falling
// back to an unverified fetch. Opting in and then silently skipping the
// versions nobody got round to is how a control becomes decoration; a
// version the author did not pin is a version they have not vouched for.
func pinnedDigest(v any, version string) (string, error) {
	switch d := v.(type) {
	case nil:
		return "", nil
	case string:
		if !hex64.MatchString(d) {
			return "", fmt.Errorf("sha256 %q is not a lowercase hex SHA-256", d)
		}
		return d, nil
	case map[string]any:
		raw, ok := d[version]
		if !ok {
			return "", fmt.Errorf("sha256 is pinned for %s but not for %s, which is "+
				"the version being built — pin it or remove the others",
				strings.Join(sortedKeys(d), ", "), version)
		}
		got := str(raw)
		if !hex64.MatchString(got) {
			return "", fmt.Errorf("sha256 for %s is %q, not a lowercase hex SHA-256", version, got)
		}
		return got, nil
	default:
		return "", fmt.Errorf("sha256 must be a digest or a map of version to digest, got %T", v)
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ErrChecksumMismatch is returned when a downloaded archive does not match the
// digest its recipe's `sha:` URL declares.
var ErrChecksumMismatch = errors.New("build: source checksum mismatch")

// verifyChecksum compares what arrived against what the upstream declares.
//
// It is silent about a source with no `sha:` — 1857 of 1858 recipes are that
// case today and failing them would ship nothing — and about a git checkout,
// which has a commit rather than a hash of bytes.
//
// A checksum file that cannot be FETCHED is a different matter from one that
// disagrees, and is treated as a build failure too: "the upstream's checksum
// was unavailable, so we built anyway" is exactly the reasoning that leaves a
// verification permanently disarmed.
func (r *Runner) verifyChecksum(src source, got string) error {
	// ⛔ THE PINNED DIGEST IS CHECKED FIRST, AND IT IS THE STRONGER CONTROL.
	// `sha:` names a .sha256 served by the same host as the archive, so it
	// catches corruption and not substitution; fetch.Pin is trust on first
	// use and by construction cannot refuse a FIRST fetch — it records it.
	// Only a digest written into the recipe by whoever read the release
	// covers that case, and it needs no network to do it.
	if src.sha256 != "" {
		if src.git {
			return fmt.Errorf("%w: %s pins a sha256 and is a git checkout — a commit "+
				"is not a hash of bytes, so the pin can never be checked",
				ErrChecksumMismatch, src.url)
		}
		if !strings.EqualFold(src.sha256, got) {
			return fmt.Errorf("%w: %s\n  pinned by the recipe: %s\n  actually arrived: %s",
				ErrChecksumMismatch, src.url, src.sha256, got)
		}
		logf("source digest matches the recipe's pin")
	}
	if src.sha == "" || src.git || r.FetchSHA == nil {
		return nil
	}
	want, err := r.FetchSHA(src.sha, src.url)
	if err != nil {
		return err
	}
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("%w: %s\n  declared by %s: %s\n  actually arrived: %s",
			ErrChecksumMismatch, src.url, src.sha, want, got)
	}
	logf("source checksum verified against %s", src.sha)
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// copyPropsTree recursively copies src into dst, preserving each file's
// permission bits (patches ship 0644, helper scripts may be executable). Every
// filesystem call goes through an os seam so all error branches are testable.
func copyPropsTree(src, dst string) error {
	info, err := osStat(src)
	if err != nil {
		return err
	}
	if err := osMkdirAll(dst, info.Mode().Perm()|0o700); err != nil {
		return err
	}
	entries, err := osReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		sp, dp := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyPropsTree(sp, dp); err != nil {
				return err
			}
			continue
		}
		fi, err := osStat(sp)
		if err != nil {
			return err
		}
		data, err := osReadFile(sp)
		if err != nil {
			return err
		}
		if err := osWriteFile(dp, data, fi.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

// buildDirListing says what the build directory holds, when the failure is a
// step that could not find a file in it.
//
// `run: fork/exec …/build/configure: no such file or directory` is the whole
// of what four gen1 packages reported, and it is not enough to act on: the
// script ran, the `cd` into the directory succeeded, and the one thing the
// message asserts — that `configure` is not there — is the thing a reader
// most wants corroborated. Two very different stories fit it. The directory
// is empty, so the source never landed; or the source landed and `configure`
// sits one level down, which is a strip-components fault. Nothing in the log
// separated them, and the class stayed open for a day.
//
// So the error carries the answer. An empty directory says so in those words,
// because "0 entries" is the single most informative thing this can report.
//
// Attached only when the error mentions a path under the build directory. A
// compiler error or a failing test has nothing to do with this listing, and a
// diagnostic that prints for every failure is one readers learn to skip.
func buildDirListing(dir string, cause error) string {
	if dir == "" || cause == nil || !strings.Contains(cause.Error(), dir) {
		return ""
	}
	ents, err := osReadDir(dir)
	if err != nil {
		return fmt.Sprintf("\n  (%s could not be read: %v)", dir, err)
	}
	if len(ents) == 0 {
		return fmt.Sprintf("\n  %s is EMPTY — the source never landed there", dir)
	}
	// Answer the question the error asked, instead of leaving it to a reader
	// with a truncated alphabetical list. The first version printed twelve
	// names and `configure` sorts after every capital letter in ASCII, so for
	// gnu.org/bash it fell into "… and 115 more" and the one thing worth
	// knowing was the one thing not shown.
	if named := missingName(cause, dir); named != "" {
		if fi, err := osStat(filepath.Join(dir, named)); err == nil {
			return fmt.Sprintf("\n  but %s IS there (%s, %d bytes) — so the exec failed for another reason: "+
				"an interpreter its #! names, or an ELF whose loader is absent",
				named, fi.Mode(), fi.Size())
		}
	}
	const show = 12
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() {
			n += "/"
		}
		names = append(names, n)
		if len(names) == show {
			break
		}
	}
	more := ""
	if len(ents) > show {
		more = fmt.Sprintf(" … and %d more", len(ents)-show)
	}
	return fmt.Sprintf("\n  %s holds %s: %s%s", dir,
		plural(len(ents), "entry", "entries"), strings.Join(names, " "), more)
}

// countEntries is how many things a fetch put in the build directory, or -1
// when the directory cannot be read.
//
// -1 rather than 0: a directory that cannot be read and one that is empty are
// different facts, and the whole point of this line is to tell them apart.
func countEntries(dir string) int {
	ents, err := osReadDir(dir)
	if err != nil {
		return -1
	}
	return len(ents)
}

// plural renders a count with the right noun, and says so when the count
// could not be taken at all.
func plural(n int, one, many string) string {
	switch {
	case n < 0:
		return "an unreadable number of " + many
	case n == 1:
		return "1 " + one
	default:
		return fmt.Sprintf("%d %s", n, many)
	}
}

// missingName is the file an exec failure named, when it names one inside
// dir. "fork/exec <dir>/configure: no such file or directory" yields
// "configure".
//
// Only a direct child: a deeper path is a different question, and guessing
// at one would put a wrong answer in an error message.
func missingName(cause error, dir string) string {
	msg := cause.Error()
	i := strings.Index(msg, dir+string(filepath.Separator))
	if i < 0 {
		return ""
	}
	rest := msg[i+len(dir)+1:]
	if j := strings.IndexAny(rest, ": \t\n"); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" || strings.Contains(rest, string(filepath.Separator)) {
		return ""
	}
	return rest
}
