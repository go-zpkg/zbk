package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/target"
)

// sourceAttestations and sourcePuller are seams: the tests drive the whole
// round trip without a registry.
var (
	sourceAttestations = func(dist, project, ver, osn, arch string) ([]artifact.Referrer, error) {
		c, err := artifact.NewOCIClient(dist)
		if err != nil {
			return nil, err
		}
		refs, _, err := c.FetchAttestations(project, ver, osn, arch)
		return refs, err
	}
	sourcePuller = func(mirror, sha256hex string) ([]byte, error) {
		c, err := artifact.NewOCIClient(mirror)
		if err != nil {
			return nil, err
		}
		return c.PullSource(sourceMirrorProject, sha256hex)
	}
)

// attestedSource is one entry of an artifact's provenance: the archive it was
// built from, and the digest that names it in the mirror.
type attestedSource struct {
	URI    string
	SHA256 string
}

// sourcesAttestedBy reads the in-toto provenance of a published artifact and
// returns the sources it names.
//
// The digest is the whole point. A URI can 404, be re-cut at different content,
// or — for the 165 pantry recipes that build from a `/archive/refs/tags/`
// tarball GitHub GENERATES on request — never have been a stored artefact at
// all. The sha256 in `resolvedDependencies` is what the signature covers, and
// it is the mirror's address.
func sourcesAttestedBy(refs []artifact.Referrer) ([]attestedSource, error) {
	var raw []byte
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			raw = r.Blob
			break
		}
	}
	if raw == nil {
		return nil, errors.New("the artifact carries no provenance attestation")
	}
	var stmt struct {
		Predicate struct {
			BuildDefinition struct {
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("provenance: %w", err)
	}
	var out []attestedSource
	for _, d := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if h := d.Digest["sha256"]; h != "" {
			out = append(out, attestedSource{URI: d.URI, SHA256: h})
		}
	}
	if len(out) == 0 {
		// A git-built recipe attests a commit rather than an archive digest,
		// and there is nothing content-addressed to fetch. Say which it is.
		return nil, errors.New("the provenance names no source archive digest")
	}
	return out, nil
}

// sourceOutputName picks a filename for a fetched source: the last segment of
// the attested URI's PATH, falling back to the digest when there is none.
//
// The digest is the identity; the name is a convenience. Parse the URI rather
// than slicing the string: `path.Base("https://x/")` is "x" — the HOST — and
// `path.Base` of a URI with a query keeps the query in the filename. What makes
// the result safe is that `path.Base` yields a single segment with no
// separator, so a URI full of `../` cannot reach out of the caller's directory;
// only ".", ".." and the empty string still need turning away.
func sourceOutputName(s attestedSource) string {
	u, err := url.Parse(s.URI)
	if err != nil {
		return s.SHA256
	}
	p := u.Path
	if p == "" {
		p = u.Opaque // git+https://… and other opaque forms
	}
	switch base := path.Base(p); base {
	case "", ".", "..", "/":
		return s.SHA256
	default:
		return base
	}
}

// runSource fetches the source a published artifact attests it was built from.
//
// This is the consuming half of the source mirror (go-zpkg/bk#127): the
// populating half keeps every archive a build downloads, addressed by its
// sha256, and until something reads it back a mirror is a claim rather than a
// capability.
func runSource(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("source", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", artifact.DistBase, "the registry the artifact was published to")
	mirror := fs.String("mirror", envOr("SOURCE_MIRROR", "oci://ghcr.io/go-zpkg"), "the source mirror to read from")
	out := fs.String("o", "", "write the archive here (default: its name in the current directory)")
	show := fs.Bool("print", false, "print what the artifact attests and fetch nothing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(stderr, "usage: zpkb source [--dist d] [--mirror m] [-o file] [--print] <project> <version>")
		return 2
	}
	project, ver := rest[0], rest[1]

	tgt, err := target.Resolve()
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	refs, err := sourceAttestations(*dist, project, ver, tgt.Platform, tgt.Arch)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s %s (%s/%s): %v\n", project, ver, tgt.Platform, tgt.Arch, err)
		return 1
	}
	srcs, err := sourcesAttestedBy(refs)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s %s: %v\n", project, ver, err)
		return 1
	}
	if *show {
		for _, s := range srcs {
			fmt.Fprintf(stdout, "%s  %s\n", s.SHA256, s.URI)
		}
		return 0
	}
	if len(srcs) > 1 && *out != "" {
		fmt.Fprintf(stderr, "error: %s %s attests %d sources; -o names one file\n", project, ver, len(srcs))
		return 2
	}
	for _, s := range srcs {
		data, err := sourcePuller(*mirror, s.SHA256)
		if err != nil {
			if errors.Is(err, artifact.ErrSourceAbsent) {
				// The distinction that matters: the artifact is fine and the
				// mirror simply never saw this build. Fetching the URI instead
				// would be a DIFFERENT artefact unless it still hashes right.
				fmt.Fprintf(stderr, "error: the mirror does not hold %s (%s)\n", s.SHA256, s.URI)
			} else {
				fmt.Fprintf(stderr, "error: %s: %v\n", s.SHA256, err)
			}
			return 1
		}
		name := *out
		if name == "" {
			name = sourceOutputName(s)
		}
		if err := os.WriteFile(name, data, 0o644); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%s  %s  (%d bytes)\n", name, s.SHA256, len(data))
	}
	return 0
}
