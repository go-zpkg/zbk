package main

import (
	"fmt"
	"strconv"

	"github.com/go-zpkg/bottle"
)

// ⛔ A REBUILD THAT REPLACES ITS TAG CANNOT BE DISTINGUISHED FROM WHAT IT
// REPLACED, AND THAT IS THE WHOLE PROBLEM.
//
// Measured 2026-11-02: go-zpkg/packages#399 gave fftw.org SIMD codelets, the
// darwin lane rebuilt it, and the result went out as `3.3.11` — the same tag
// the scalar build had. `nm` showed 0 → 207 `_neon` symbols, so the bottles
// are plainly different; nothing in the registry says so. Anyone holding the
// old one keeps it, and "did I get the SIMD build?" is unanswerable from the
// version.
//
// `_N` is the answer bottle already understood and nothing produced: it
// parses, it sorts after the build it supersedes, and an exact pin tells the
// two apart (bottle's rebuild_test.go). This is the half that mints it.
//
// ⛔ OPT-IN, AND DELIBERATELY NOT FOLDED INTO --force. Every manual dispatch
// of the darwin lane already sets FORCE=1 — the workflow does it
// unconditionally, after three openssl relinks came back "successful" having
// rebuilt nothing. If force alone minted a counter, re-running a lane that
// failed at the publish step would bump N every attempt and litter the
// registry with tags nobody asked for. A rebuild that SUPERSEDES is a
// decision about meaning, so it is stated rather than inferred.

// nextRebuild is the rebuild counter a new build of an already-published
// (project, version, platform) should carry: one more than the highest
// already there.
//
// ⛔ IT COUNTS WHAT IS PUBLISHED FOR THIS PLATFORM, not what is tagged. A tag
// listing spans every platform — bottle's own VersionsFor says so — so a
// darwin rebuild must not take its number from a linux one. Getting that
// wrong would leave a gap on one platform and a collision on the other.
//
// Versions whose numeric components differ are ignored: `3.3.12_4` says
// nothing about how many times `3.3.11` has been rebuilt.
func nextRebuild(project, version, osn, arch string) (int, error) {
	want := bottle.ParseVer(version)
	// The same seams `bk catalog` reads through, so the number minted here
	// and the catalogue's idea of what exists cannot come from two different
	// readings of the registry.
	all, _, err := versionsFor(project, osn, arch)
	if err != nil {
		return 0, fmt.Errorf("cannot read the published versions of %s: %w", project, err)
	}
	highest := -1
	for _, v := range all {
		if !sameNums(v, want) {
			continue
		}
		_, published, perr := publishedTagFor(project, v, osn, arch)
		if perr != nil {
			// ⛔ "I could not ask" is not "it is not there". Guessing the next
			// number from a partial listing is how two builds collide on one
			// tag, so the caller is told instead.
			return 0, fmt.Errorf("cannot tell whether %s %s is published for %s/%s: %w",
				project, v.Raw, osn, arch, perr)
		}
		if !published {
			continue
		}
		if v.Rebuild > highest {
			highest = v.Rebuild
		}
	}
	if highest < 0 {
		// Nothing of this version is published here, so a rebuild counter
		// would be a claim about a predecessor that does not exist.
		return 0, nil
	}
	return highest + 1, nil
}

// sameNums reports whether two versions differ only by their rebuild counter.
func sameNums(a, b bottle.Ver) bool {
	if len(a.Nums) != len(b.Nums) {
		return false
	}
	for i := range a.Nums {
		if a.Nums[i] != b.Nums[i] {
			return false
		}
	}
	return true
}

// rebuiltVersion is `version` with the counter appended, or `version`
// unchanged when nothing of it is published here yet.
func rebuiltVersion(version string, n int) string {
	if n == 0 {
		return version
	}
	return version + "_" + strconv.Itoa(n)
}
