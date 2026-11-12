package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/bottlepkg"
	"github.com/go-zpkg/zbk/build"
	"github.com/go-zpkg/zbk/fetch"
	"github.com/go-zpkg/zbk/fixup"
	"github.com/go-zpkg/zbk/recipefile"
	"github.com/go-zpkg/zbk/target"
	"github.com/go-zpkg/zbk/versions"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// buildFactory builds a wired Runner; overridden in tests.
var buildFactory = realBuildRunner

// lookPath resolves a binary name to an absolute path; a seam for tests.
var lookPath = exec.LookPath

// newInterp constructs the pure-Go shell interpreter; a seam so runBash's
// constructor-error branch is testable.
var newInterp = interp.New

// pickVersion adapts bottle.PickVersion (which returns a Ver) to the Runner's
// string-version contract.
func pickVersion(project, constraint string) (string, error) {
	v, err := bottle.PickVersion(project, constraint)
	return v.Raw, err
}

// toolInstallable answers the question bootstrap actually has: can this
// registry give the build this TOOL — not "does a version of it exist".
//
// The two differ, and the difference stopped the s390x seed.
// github.com/besser82/libxcrypt build-depends on perl.org; perl.org was in the
// seed registry, so a version check said yes; and the build died because
// installing perl needs libcrypt, which the soname map answers with
// github.com/besser82/libxcrypt — the project being built.
//
// Resolved for the HOST's platform, because a build dependency is something
// that RUNS here. The link closure, which is built for the target, goes
// through pickVersion and is untouched by this.
func toolInstallable(project, constraint string) (string, error) {
	osn, arch := bottle.HostSlug()
	v, err := bottle.PickVersionFor(project, constraint, osn, arch)
	if err != nil {
		return "", err
	}
	if _, err := bottle.ResolveClosureFor(map[string]string{project: constraint}, osn, arch); err != nil {
		return "", fmt.Errorf("%s %s is here but its closure is not: %w", project, v.Raw, err)
	}
	return v.Raw, nil
}

// runBash executes the generated build script under the sanitized env using
// mvdan.cc/sh's pure-Go interpreter — no `/bin/bash` binary. External build
// tools (gcc/make/cmake/pkgx) are still exec'd (that is the pkgx toolchain, not
// a shell dependency); only the shell language itself runs in-process.
func runBash(scriptPath string, env []string) error {
	return runBashTo(os.Stdout, os.Stderr)(scriptPath, env)
}

// runBashTo is runBash with the script's streams redirected. The factory points
// both at one writer (as factory.sh's `2>&1` did) so a failed build's error tail
// can be captured verbatim into failures-detail.txt.
func runBashTo(out, errOut io.Writer) func(string, []string) error {
	return runBashLimited(0, out, errOut)
}

// runBashLimited is runBashTo with a deadline; 0 means none, which is what a
// BUILD gets — a compile that takes an hour is a compile, and a factory that
// killed one would be inventing failures.
//
// A recipe's TEST is the other case. It runs after the build, in a chunk that
// must finish, and one that waits on a socket nobody will answer hangs the
// whole run rather than the package. mvdan.cc/sh's interpreter takes the
// context, so the limit reaches the running script rather than only the
// goroutine waiting on it.
func runBashLimited(limit time.Duration, out, errOut io.Writer) func(string, []string) error {
	return func(scriptPath string, env []string) error {
		f, err := os.Open(scriptPath)
		if err != nil {
			return err
		}
		defer f.Close()
		prog, err := syntax.NewParser().Parse(f, scriptPath)
		if err != nil {
			return fmt.Errorf("parse %s: %w", scriptPath, err)
		}
		// Watched for an OOM kill on the way past. This is the only layer that
		// has the bytes: the compiler driver reaps its own cc1plus and exits 1,
		// so by the time the error reaches the caller the signal is gone. See
		// oomSignatures.
		oom := &oomSniffer{w: out}
		oomErr := oom
		if errOut != out {
			oomErr = &oomSniffer{w: errOut}
		}
		r, err := newInterp(
			interp.Env(expand.ListEnviron(env...)),
			interp.StdIO(os.Stdin, oom, oomErr),
		)
		if err != nil {
			return err
		}
		ctx := context.Background()
		if limit > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, limit)
			defer cancel()
		}
		err = r.Run(ctx, prog)
		if err != nil && (oom.seen || oomErr.seen) {
			return fmt.Errorf("%w — a compiler was KILLED: the machine ran OUT OF MEMORY, "+
				"and the recipe is not what needs changing. Give it swap, or fewer parallel jobs", err)
		}
		return err
	}
}

// realBuildRunner wires the real bk/bottle implementations into a Runner. Every
// field but pickVersion/runBash is a direct package function of matching shape.
func realBuildRunner(zpkgxBin string) *build.Runner {
	return &build.Runner{
		PickVersion:     pickVersion,
		ResolveVersion:  versions.Resolve,
		Fetch:           fetch.Fetch,
		FetchGit:        fetch.FetchGit,
		FetchSHA:        fetch.DeclaredSHA256,
		Touch:           build.TouchAutotools,
		Run:             runBash,
		FixUp:           fixup.FixUp,
		WriteBottle:     bottlepkg.WriteBottle,
		ResolveDep:      pickVersion,
		ToolInstallable: toolInstallable,
		ZpkgxBin:        zpkgxBin,
		BashPath:        "/bin/bash",
	}
}

// runBuild is the `bk build` subcommand: read a recipe, resolve the target, and
// run the full pipeline (fetch → deps → generate → run → fix-up → package).
func runBuild(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", "", "output dir for the packaged bottle (omit to skip packaging)")
	recipe := fs.String("recipe", "", "path to the package.yml recipe (required)")
	version := fs.String("version", "", "exact version to build (default: latest resolvable)")
	// ⛔ THE DEFAULT IS `zpkgx`, THE BINARY WE SHIP. It was `pkgx` until
	// 2026-11-10, which is a name nothing in this organisation installs — and
	// upstream's `pkgx` is a plausible thing to find on a developer's PATH, so
	// the failure was not "command not found" but a build resolved against
	// SOMEBODY ELSE'S pantry. The five factory workflows passed
	// `--zpkgx "$(command -v zpkgx)"` and never saw it.
	zpkgx := fs.String("zpkgx", "zpkgx", "path to the zpkgx binary used for the deps env")
	libc := fs.String("libc", "", `C library to link against: "zpkgx" targets the gnu.org/glibc bottle (sovereign FROM-scratch, linux, C recipes); default keeps the build container's system glibc`)
	glibc := fs.String("glibc", "", `with --libc=zpkgx, pin the exact glibc version to link against, e.g. -glibc 2.27.0 (a chosen HPC floor); default newest`)
	jobs := fs.Int("jobs", envInt("JOBS"), "parallelism handed to a recipe's build (`hw.concurrency`); 0 = one per CPU")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if *recipe == "" || len(rest) < 1 {
		fmt.Fprintln(stderr, "usage: bk build --recipe <package.yml> [--dist <out>] <project>")
		return 2
	}
	project := rest[0]

	// Resolve the pkgx binary to an absolute path: the build script runs under a
	// sanitized PATH (/usr/bin:/bin:/usr/sbin:/sbin) that excludes /usr/local/bin
	// and ~/.local/bin, so a bare "pkgx" would not be found for the deps eval. If
	// resolution fails, keep the value as given (explicit paths still work and the
	// original error stays clear).
	zpkgxBin := *zpkgx
	if abs, err := lookPath(zpkgxBin); err == nil {
		zpkgxBin = abs
	}

	runner := buildFactory(zpkgxBin)
	runner.RecipeDir = filepath.Dir(*recipe)
	runner.LibcMode = *libc
	runner.Glibc = *glibc
	runner.Concurrency = *jobs

	// By extension: --recipe takes a path, and `package.hcl` is a recipe like
	// any other. Reading it as YAML made HCL recipes unbuildable by name.
	rec, err := recipefile.LoadFile(*recipe)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	tgt, err := target.Resolve()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	// A pinned --version becomes an exact `=` semver constraint so the resolver
	// selects precisely that candidate; empty keeps the default "*" (latest).
	constraint := "*"
	if *version != "" {
		constraint = "=" + *version
	}

	res, err := runner.Build(rec, project, constraint, tgt, target.Host(), *dist)
	if err != nil {
		fmt.Fprintln(stderr, "build failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "built %s %s → %s\n", project, res.Version, res.Install)
	// Say what it was built FROM, on the same screen as what came out. A digest
	// nobody ever sees is a digest nobody compares.
	if d := res.Source.SHA256 + res.Source.Commit; d != "" {
		fmt.Fprintf(stdout, "source: %s (%s)\n", res.Source.URI, d)
	}
	if res.BottlePath != "" {
		fmt.Fprintln(stdout, "bottle:", res.BottlePath)
	}
	return 0
}
