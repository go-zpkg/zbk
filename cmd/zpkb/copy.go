package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/go-zpkg/bottle"
)

// runCopy implements `zpkb copy`: move published bottles from one OCI namespace
// to another, with their signatures and attestations.
//
// ⛔⛔ IT IS NOT HOW A REGISTRY NAMESPACE IS MOVED, AND IT WAS WRITTEN
// BELIEVING IT WAS.
//
// The premise was sound as far as it went: GitHub's container packages are
// org-scoped and did not follow the repository transfer — every repository went
// from go-pkgx to go-zpkg and every bottle stayed, `DistBase` was rewritten to
// match, and v0.64.0 through v0.68.0 shipped a fleet pointing at an EMPTY
// registry (bottle's TestTheDefaultRegistryHoldsBottles is the gate that came
// out of it). So the new namespace has to be POPULATED.
//
// It is populated by BUILDING CORRECT RECIPES INTO IT. Every bottle in the old
// namespace was built from `pkgxdev/pantry`'s recipes, which go-zpkg/packages
// #431 established can be neither read nor copied — its `git ls-files` over
// 2453 upstream files finds no LICENSE and no COPYING — and that issue's own
// item 1 drew the consequence: "the sovereign pantry is WRITTEN, not converted,
// and the order of work changes completely". Transplanting those bottles would
// carry their measured defects forward by digest, and
// go-zpkg/packages/.github/workflows/wasip1.yml:201 states the rest: "Nothing
// in go-pkgx carries a build identity — it predates them."
//
// go-zpkg/packages#440 carries the corrected order. What is left for this verb
// is the case where republishing verbatim is the POINT rather than a shortcut:
// a mirror (go-zpkg/mirror; `zpkb mirroraudit` opens with "A mirrored bottle is
// republished verbatim"). It has no caller in the migration.
//
// ⛔ IT VERIFIES AT THE DESTINATION BY DEFAULT, because "the bytes arrived" is
// not the question. A cosign signature is a REFERRER of a platform manifest,
// not a child of it, so a copy can move a byte-identical bottle and leave its
// signature behind; bottle.CopyPublished was written with exactly that defect
// and its test caught it. A copy whose result cannot be verified is worse than
// one that failed, because `zpkgs install` verifies by default — the failure
// would surface at install time, to a user, as a trust error.
func runCopy(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("copy", flag.ContinueOnError)
	fset.SetOutput(stderr)
	from := fset.String("from", "", "the OCI namespace to read, e.g. oci://ghcr.io/go-pkgx/packages")
	to := fset.String("to", "", "the OCI namespace to write, e.g. oci://ghcr.io/go-zpkg/packages")
	project := fset.String("project", "", "the project to copy, e.g. gnu.org/bash")
	version := fset.String("version", "", "one version to copy (default: every version the source publishes)")
	dryRun := fset.Bool("dry-run", false, "say which versions would be copied and copy nothing")
	// The opt-out is named for what it gives up, not for what it saves. There is
	// no --verify: verification is the point, so it is not a feature to turn on.
	noVerify := fset.Bool("no-verify", false,
		"do not check at the destination that each copied bottle still verifies (it is checked by default)")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if *from == "" || *to == "" || *project == "" {
		fmt.Fprintln(stderr, "zpkb copy: --from, --to and --project are all required")
		return 2
	}

	src, err := bottle.NewOCIClient(*from)
	if err != nil {
		fmt.Fprintln(stderr, "zpkb copy: --from:", err)
		return 2
	}
	dst, err := bottle.NewOCIClient(*to)
	if err != nil {
		fmt.Fprintln(stderr, "zpkb copy: --to:", err)
		return 2
	}

	versions, err := copyVersions(src, *project, *version)
	if err != nil {
		fmt.Fprintln(stderr, "zpkb copy:", err)
		return 1
	}
	if len(versions) == 0 {
		// ⛔ NOT A SUCCESS. "Nothing to copy" and "the source publishes nothing
		// under that name" print the same empty output, and this fleet has
		// published that zero before: a sweep that cannot read a corpus reports
		// what a clean one reports.
		fmt.Fprintf(stderr, "zpkb copy: %s publishes no version in %s\n", *project, *from)
		return 1
	}

	if *dryRun {
		for _, v := range versions {
			fmt.Fprintf(stdout, "would copy %s %s\n", *project, v)
		}
		fmt.Fprintf(stdout, "%d version(s), %s -> %s\n", len(versions), *from, *to)
		return 0
	}

	ctx := context.Background()
	for _, v := range versions {
		if _, err := copyPublished(ctx, src, dst, *project, v); err != nil {
			fmt.Fprintln(stderr, "zpkb copy:", err)
			return 1
		}
		if *noVerify {
			fmt.Fprintf(stdout, "copied %s %s (not verified)\n", *project, v)
			continue
		}
		n, err := verifyAtDestination(dst, *project, v)
		if err != nil {
			fmt.Fprintf(stderr, "zpkb copy: %s %s copied but does not verify at %s: %v\n", *project, v, *to, err)
			return 1
		}
		fmt.Fprintf(stdout, "copied %s %s, %d platform(s) verified\n", *project, v, n)
	}
	return 0
}

// copyVersions is the list of versions to copy: the one named, or every version
// tag the source publishes for the project.
//
// bottle.IsVersionTag is what decides, rather than a rule restated here. A tag
// listing also carries `<ver>--<os>-<arch>` platform tags and the
// `sha256-<digest>` referrer tags ghcr uses in place of a referrers API, and
// counting those as versions is a mistake this fleet has already published —
// "2 version(s) tagged", the two being referrers.
func copyVersions(src *bottle.OCIClient, project, one string) ([]string, error) {
	if one != "" {
		return []string{one}, nil
	}
	tags, err := src.ListTags(project)
	if err != nil {
		return nil, fmt.Errorf("list the tags of %s: %w", project, err)
	}
	var out []string
	for _, t := range tags {
		if bottle.IsVersionTag(t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// The two seams. Both halves of this command talk to a registry, so without
// them every branch below would need a registry to reach — and bottle already
// owns the fixture that proves the COPY works. These let the verb's own
// decisions (which versions, what to print, what to exit with) be driven
// without one, which is the only part that lives here.
var (
	copyPublished       = bottle.CopyPublished
	verifyAtDestination = verifyCopied
)

// copyVerifier is the destination's verification surface, as an interface so a
// test can answer it. *bottle.OCIClient satisfies it.
type copyVerifier interface {
	Platforms(project, ver string) ([]string, error)
	BottleDigest(project, ver, osn, arch string) (string, error)
	VerifyBottleDigest(project, ver, osn, arch, digest string) error
}

// verifyCopied checks every platform of a version AT THE DESTINATION with the
// install path's own signature check, and returns how many it checked.
//
// It verifies by DIGEST, so nothing is downloaded twice: the bottle tarball
// stays in the registry and only its manifest and signature are read.
//
// ⛔ ZERO PLATFORMS IS A FAILURE. A version whose index arrived without the
// manifests it names would otherwise report "0 platform(s) verified" and a
// zero exit, which is the shape of a copy that moved an index and left the
// bottles behind.
func verifyCopied(dst copyVerifier, project, ver string) (int, error) {
	platforms, err := dst.Platforms(project, ver)
	if err != nil {
		return 0, err
	}
	if len(platforms) == 0 {
		return 0, fmt.Errorf("the index names no platform")
	}
	for _, p := range platforms {
		osn, arch, ok := strings.Cut(p, "/")
		if !ok {
			return 0, fmt.Errorf("unreadable platform %q", p)
		}
		digest, err := dst.BottleDigest(project, ver, osn, arch)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", p, err)
		}
		if err := dst.VerifyBottleDigest(project, ver, osn, arch, digest); err != nil {
			return 0, fmt.Errorf("%s: %w", p, err)
		}
	}
	return len(platforms), nil
}
