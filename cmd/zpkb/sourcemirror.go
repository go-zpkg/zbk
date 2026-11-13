package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/fetch"
)

// sourceMirrorProject is the single repository the mirror lives in.
//
// One repository, not one per project, because the store is addressed by
// CONTENT: the tag is the archive's sha256, so which project happened to fetch
// it first is not part of its identity. Two recipes that build from the same
// tarball share one object rather than two.
const sourceMirrorProject = "sources"

// newSourceStore is a seam: the tests drive the hook without a registry.
var newSourceStore = func(base string) (sourceStore, error) {
	c, err := bottle.NewOCIClient(base)
	if err != nil {
		return nil, err
	}
	return ociSourceStore{c}, nil
}

// sourceStore is the half of bottle's source API this needs.
type sourceStore interface {
	HasSource(project, sha256hex string) (bool, error)
	PushSource(project string, data []byte, uri string) error
	PinnedDigest(project, uri string) (string, error)
}

type ociSourceStore struct{ c *bottle.OCIClient }

func (s ociSourceStore) HasSource(project, sha string) (bool, error) {
	return s.c.HasSource(project, sha)
}

func (s ociSourceStore) PinnedDigest(project, uri string) (string, error) {
	return s.c.PinnedDigest(project, uri)
}

func (s ociSourceStore) PushSource(project string, data []byte, uri string) error {
	_, err := s.c.PushSource(project, data, uri)
	return err
}

// installSourceMirror points fetch.Mirror at a source store, so every archive a
// build downloads is kept.
//
// Populating only. Consuming it — fetching FROM the mirror when a recipe
// declares a digest — is a separate change, and this one has to run first: a
// store nobody has written to is not worth reading.
//
// Every failure here is reported and swallowed. A build that already holds the
// bytes it needs must not die because a registry was unreachable; the mirror
// serves the next rebuild, not this one. Silence would be the wrong choice for
// the same reason it is everywhere else in this factory — a mirror that quietly
// stopped recording would look exactly like one that had nothing to record.
func installSourceMirror(base string, stderr io.Writer, strict bool) error {
	store, err := newSourceStore(base)
	if err != nil {
		return fmt.Errorf("source mirror %s: %w", base, err)
	}
	fetch.Pin = pinChecker(store, stderr, strict)
	fetch.Mirror = func(path, sha, url string) {
		switch have, err := store.HasSource(sourceMirrorProject, sha); {
		case err != nil:
			fmt.Fprintf(stderr, "source mirror: checking %s: %v\n", sha, err)
			return
		case have:
			// The tag IS the content, so this is not an optimisation: pushing
			// again would write the same manifest. It is megabytes not spent.
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "source mirror: reading %s: %v\n", path, err)
			return
		}
		if err := store.PushSource(sourceMirrorProject, data, url); err != nil {
			fmt.Fprintf(stderr, "source mirror: storing %s (%s): %v\n", sha, url, err)
			return
		}
		fmt.Fprintf(stderr, "source mirror: stored %s (%d KiB) from %s\n", sha, len(data)/1024, url)
	}
	return nil
}

// pinChecker is the consuming half of the source mirror: it asks what this URL
// served last time and refuses bytes that disagree.
//
// Three outcomes, and the third is a decision rather than an oversight.
//
//  1. No pin — the first time this URL has been fetched. Recorded by the
//     Mirror hook that runs next. A version bump lands here, because the
//     version is in the URL: a new release asks a question never asked
//     before. That is why there is no --no-pin escape; the case it would
//     serve does not arise.
//
//  2. A pin that differs — the SAME URL serving different bytes. Refused,
//     naming both digests. A re-cut release, a compromised mirror, a hijacked
//     domain: the cases nothing else in this factory would notice.
//
//  3. The store cannot answer. Warned about and allowed through by default,
//     refused under -source-pin-strict. This is the uncomfortable one. An
//     unreachable registry is not evidence of tampering, and the mirror's
//     whole stated contract is that a build must not die because a registry
//     was down — but "cannot read the pin" and "there is no pin" are not the
//     same fact, and treating them alike is how trust-on-first-use quietly
//     becomes trust-every-time. So they are distinguished here, said out
//     loud, and which one is fatal is the operator's choice. bottle's
//     PinnedDigest refuses to conflate them, which is what makes the choice
//     available at all.
func pinChecker(store sourceStore, stderr io.Writer, strict bool) func(string, string) error {
	return func(url, sha string) error {
		want, err := store.PinnedDigest(sourceMirrorProject, url)
		switch {
		case errors.Is(err, bottle.ErrSourceAbsent):
			return nil
		case err != nil:
			if strict {
				return fmt.Errorf("source pin: cannot read the pin for %s: %w", url, err)
			}
			fmt.Fprintf(stderr, "source pin: cannot read the pin for %s: %v (allowing; -source-pin-strict refuses)\n", url, err)
			return nil
		case want != sha:
			return fmt.Errorf("%w: %s now serves %s, and served %s before",
				fetch.ErrSourcePinMismatch, url, sha, want)
		}
		fmt.Fprintf(stderr, "source pin: %s matches what %s served before\n", sha, url)
		return nil
	}
}
