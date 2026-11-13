package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/target"
)

// A resolvedDependency that names a BUILD ENVIRONMENT entry carries a purl
// rather than a source archive's digest — see [cutPurl] and [purlFor].
//
// The two live in the same SLSA list and are told apart by shape, not by
// position: a source material carries a sha256 of bytes that were fetched, an
// environment material carries a purl and no digest, because we have the
// version the build resolved and not the bytes it read. `zbk source` already
// filters on "has a sha256", so the two readers do not see each other's
// entries.

// attestedEnv is one entry of a published bottle's recorded build environment.
type attestedEnv struct {
	Project string
	Version string
}

// envAttestedBy reads the build environment a published bottle records.
//
// ⛔ "NOT RECORDED" AND "COULD NOT BE READ" ARE DIFFERENT ANSWERS, and this
// returns them as different errors, because every bottle published before
// bk v0.17.0 records nothing and a sweep that folded those into failures
// would report the whole registry as broken.
func envAttestedBy(refs []bottle.Referrer) ([]attestedEnv, error) {
	var raw []byte
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			raw = r.Blob
			break
		}
	}
	if raw == nil {
		return nil, errNoProvenance
	}
	var stmt struct {
		Predicate struct {
			BuildDefinition struct {
				ResolvedDependencies []struct {
					URI string `json:"uri"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("provenance: %w", err)
	}
	var out []attestedEnv
	for _, d := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		// ⛔ BOTH SPELLINGS ARE READ HERE AND ONLY THE CURRENT ONE IS MINTED.
		// Every bottle published before the purl moved to `pkg:generic/`
		// records `pkg:pkgx/`, and this function's whole job is to answer
		// about bottles that already exist; cutPurl keeps the last-"@" rule
		// this loop used to carry.
		project, version, ok := cutPurl(d.URI)
		if !ok {
			continue
		}
		out = append(out, attestedEnv{Project: project, Version: version})
	}
	if len(out) == 0 {
		return nil, errNoEnvironment
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

var (
	errNoProvenance  = errors.New("the bottle carries no provenance attestation")
	errNoEnvironment = errors.New("the provenance records no build environment")
)

// requirement is "the build environment must hold this project at this
// version or newer" — `go.dev@1.27.2` after a Go security release.
type requirement struct {
	Project string
	Version string // "" when no requirement was given
}

func parseRequirement(s string) (requirement, error) {
	// The LAST "@", as everywhere here: a project name is a path and may
	// hold one, a version never does.
	i := strings.LastIndex(s, "@")
	if i <= 0 || i == len(s)-1 {
		return requirement{}, fmt.Errorf("%q is not project@version", s)
	}
	r := requirement{Project: s[:i], Version: s[i+1:]}
	if err := bottle.ValidateVersionString(r.Version); err != nil {
		return requirement{}, fmt.Errorf("%q: %w", s, err)
	}
	return r, nil
}

// envVerdict is what a requirement says about one bottle's recorded environment.
type envVerdict int

const (
	// vUnknown: the bottle records no environment, so nothing can be said.
	// Every bottle published before bk v0.17.0 is here.
	vUnknown envVerdict = iota
	// vStale: it records the project, at an older version. Rebuild.
	vStale
	// vOK: it records the project, at or above the wanted version.
	vOK
	// ⛔ vNotUsed: it records an environment, and this project is not in it.
	//
	// Neither stale nor ok, and keeping it apart is the whole care in this
	// function. A C package has no `go.dev`: counted as STALE it would
	// rebuild the world for a Go release, and counted as OK it would make
	// the figure meaningless. The same mistake a denylist makes when it
	// inherits a taxonomy's blind spot.
	vNotUsed
)

// judge applies a requirement to one bottle's recorded environment.
func judge(env []attestedEnv, want requirement) envVerdict {
	if len(env) == 0 {
		return vUnknown
	}
	for _, e := range env {
		if e.Project != want.Project {
			continue
		}
		if bottle.ParseVer(e.Version).Satisfies(">=" + want.Version) {
			return vOK
		}
		return vStale
	}
	return vNotUsed
}

// runBuildEnv reports what build environment published bottles record.
//
// It exists because the question "should this be rebuilt for a toolchain
// vulnerability?" needs a BEFORE. Measured 2026-10-09, a published bottle said
// nothing at all about what compiled it: builder.id was a constant and
// buildDefinition was `{}`. bk v0.17.0 records it; this says how much of the
// registry predates that, which is what decides whether a rebuild counter can
// be derived or has to be seeded by hand.
func runBuildEnv(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("buildenv", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", bottle.DistBase, "the registry the bottles were published to")
	platform := fs.String("platform", "", "os/arch to read, e.g. linux/aarch64 (default: this machine)")
	list := fs.String("list", "", "file of `project version` lines to sweep instead of one project")
	needs := fs.String("needs", "", "judge each bottle against a requirement on its build environment, e.g. -needs go.dev@1.27.2: which bottles were built with something older, which record nothing, and which never used it at all")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	osn, arch, err := buildEnvPlatform(*platform)
	if err != nil {
		fmt.Fprintln(stderr, "buildenv:", err)
		return 2
	}

	var want requirement
	if *needs != "" {
		want, err = parseRequirement(*needs)
		if err != nil {
			fmt.Fprintf(stderr, "buildenv: -needs %v\n", err)
			return 2
		}
	}

	if *list != "" {
		return sweepBuildEnv(*list, *dist, osn, arch, want, stdout, stderr)
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: bk buildenv [--dist d] [--platform os/arch] <project> <version>")
		fmt.Fprintln(stderr, "       bk buildenv [--dist d] [--platform os/arch] --list <file>")
		return 2
	}
	proj, ver := fs.Arg(0), fs.Arg(1)
	env, err := buildEnvOf(*dist, proj, ver, osn, arch)
	if err != nil {
		fmt.Fprintf(stderr, "buildenv: %s %s (%s/%s): %v\n", proj, ver, osn, arch, err)
		return 1
	}
	for _, e := range env {
		fmt.Fprintf(stdout, "%s %s\n", e.Project, e.Version)
	}
	fmt.Fprintf(stdout, "\n%d entry(ies) recorded for %s %s on %s/%s\n", len(env), proj, ver, osn, arch)
	return 0
}

// buildEnvPlatform resolves the platform to read, defaulting to this machine.
func buildEnvPlatform(p string) (osn, arch string, err error) {
	if p == "" {
		tgt, err := target.Resolve()
		if err != nil {
			return "", "", err
		}
		return tgt.Platform, tgt.Arch, nil
	}
	osn, arch, ok := splitPlatform(p)
	if !ok {
		return "", "", fmt.Errorf("--platform %q is not os/arch", p)
	}
	return osn, arch, nil
}

// buildEnvOf fetches a published bottle's attestations and reads the build
// environment out of them.
//
// ⛔ NOT A SEAM, deliberately, and it was one for a day. sourceAttestations is
// already the seam — the layer that actually reaches the registry — so a
// second one here only hid this function's own body from the tests. The
// coverage gate counts uncovered BLOCKS and said so; `go tool cover -func`
// reported 100.0% for the same profile, which is exactly the rounding the gate
// exists to stop trusting.
func buildEnvOf(dist, proj, ver, osn, arch string) ([]attestedEnv, error) {
	refs, err := sourceAttestations(dist, proj, ver, osn, arch)
	if err != nil {
		return nil, err
	}
	return envAttestedBy(refs)
}

// sweepBuildEnv reports the three outcomes separately and counts all of them.
//
// ⛔ THE TOTALS ALWAYS, INCLUDING THE ZEROS, and "could not be read" never
// folded into "records nothing": an unreachable registry has told us nothing,
// and a sweep that reported it as an absence would be the same defect as a
// census that could not read reporting zero.
func sweepBuildEnv(path, dist, osn, arch string, want requirement, stdout, stderr io.Writer) int {
	pairs, err := readProjectVersions(path)
	if err != nil {
		fmt.Fprintln(stderr, "buildenv:", err)
		return 2
	}
	if len(pairs) == 0 {
		fmt.Fprintf(stderr, "buildenv: %s names no `project version` pair — that is a failure, not an empty registry\n", path)
		return 2
	}
	var recorded, none, unreadable int
	var stale, ok, notUsed int
	for _, pv := range pairs {
		env, err := buildEnvOf(dist, pv[0], pv[1], osn, arch)
		switch {
		case errors.Is(err, errNoEnvironment), errors.Is(err, errNoProvenance):
			none++
			fmt.Fprintf(stdout, "none    %s %s\n", pv[0], pv[1])
		case err != nil:
			unreadable++
			fmt.Fprintf(stdout, "ERROR   %s %s: %v\n", pv[0], pv[1], err)
		case want.Version == "":
			recorded++
			fmt.Fprintf(stdout, "env     %s %s: %d entry(ies)\n", pv[0], pv[1], len(env))
		default:
			recorded++
			switch judge(env, want) {
			case vStale:
				stale++
				fmt.Fprintf(stdout, "STALE   %s %s: %s %s, want >=%s\n",
					pv[0], pv[1], want.Project, versionOf(env, want.Project), want.Version)
			case vNotUsed:
				notUsed++
				fmt.Fprintf(stdout, "n/a     %s %s: does not use %s\n", pv[0], pv[1], want.Project)
			default:
				ok++
				fmt.Fprintf(stdout, "ok      %s %s: %s %s\n",
					pv[0], pv[1], want.Project, versionOf(env, want.Project))
			}
		}
	}
	fmt.Fprintf(stdout, "\n%d read · %d record a build environment · %d record none · %d unreadable\n",
		len(pairs), recorded, none, unreadable)
	if want.Version != "" {
		// ⛔ "DOES NOT USE IT" IS ITS OWN COLUMN. A C package has no
		// `go.dev`: folded into STALE it would rebuild the world for a Go
		// release, folded into OK it would make the figure meaningless.
		fmt.Fprintf(stdout, "of those: %d need rebuilding for %s>=%s · %d already have it · %d never used it\n",
			stale, want.Project, want.Version, ok, notUsed)
		// The bottles that CANNOT be judged are the ones to act on first, and
		// they are the whole registry until it has been rebuilt once under
		// bk v0.17.0 or later.
		if none > 0 {
			fmt.Fprintf(stdout, "and %d record nothing, so this says nothing about them\n", none)
		}
	}
	if none > 0 || unreadable > 0 || stale > 0 {
		return 1
	}
	return 0
}

// versionOf is the version the recorded environment holds for a project, or
// "" — used only to say WHICH version a stale bottle has, because "it is old"
// without the number sends the reader back to the registry.
func versionOf(env []attestedEnv, project string) string {
	for _, e := range env {
		if e.Project == project {
			return e.Version
		}
	}
	return ""
}

// readProjectVersions reads `project version` lines, # comments and blanks
// ignored.
func readProjectVersions(path string) ([][2]string, error) {
	b, err := osReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	for n, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch len(f) {
		case 0:
			continue
		case 2:
			out = append(out, [2]string{f[0], f[1]})
		default:
			// Named rather than skipped: a line the reader cannot use is a
			// project the sweep will not report on, and a silent skip makes
			// the totals smaller for a reason nobody can see.
			return nil, fmt.Errorf("%s:%d: want `project version`, got %q", path, n+1, strings.TrimSpace(line))
		}
	}
	return out, nil
}
