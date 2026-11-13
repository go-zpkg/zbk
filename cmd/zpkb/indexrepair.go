package main

import (
	"fmt"
	"io"

	"github.com/go-zpkg/bottle"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// published records one bottle this run put in the registry, so the index can
// be checked once the batch is over.
type published struct {
	project string
	tag     string
	desc    ocispec.Descriptor
}

// repairIndexes re-checks every index this run wrote and puts back any platform
// a racing publisher dropped after the push had already verified itself.
//
// Publishing an index is a read-modify-write on one mutable tag, and the arch
// jobs — plus the separate darwin workflow — race on it. bottle's per-push
// reconcile confirms its write twice with a settle window between, which catches
// a racer landing just behind it; it cannot catch one that lands after this
// process moved on to the next package. An audit of the live registry found 137
// versions with exactly that damage, 41 missing a linux platform, including
// gnu.org/glibc and kernel.org/linux-headers — the closure of every sovereign
// build.
//
// Running at the END is the point: by then the other publishers have finished,
// so a repair sticks. It is also cheap — one index read per bottle published,
// and nothing written in the common case.
//
// A failure here is reported, not fatal. The bottles are pushed and valid; a
// broken index is repairable by the next run, and failing the whole build over
// it would throw away work that succeeded.
func repairIndexes(dist string, pubs []published, stdout, stderr io.Writer) int {
	if len(pubs) == 0 || dist == "" {
		return 0
	}
	c, err := newOCIClient(dist)
	if err != nil {
		fmt.Fprintf(stderr, "index check: %v\n", err)
		return 0
	}
	repaired := 0
	for _, p := range pubs {
		ok, err := c.EnsureIndexed(p.project, p.tag, p.desc)
		if err != nil {
			fmt.Fprintf(stderr, "index check %s %s: %v\n", p.project, p.tag, err)
			continue
		}
		if ok {
			repaired++
			fmt.Fprintf(stdout, "🔧 REPAIRED index %s %s — a concurrent publisher had dropped this platform\n", p.project, p.tag)
		}
	}
	return repaired
}

// newOCIClient is a seam: the repair pass talks to the registry, and the tests
// drive it without one.
var newOCIClient = func(dist string) (indexEnsurer, error) { return bottle.NewOCIClient(dist) }

// indexEnsurer is the slice of the OCI client the repair pass needs.
type indexEnsurer interface {
	EnsureIndexed(project, ver string, desc ocispec.Descriptor) (bool, error)
}
