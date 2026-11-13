package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zbk/vuln"
)

// vexReferrer builds the OpenVEX document a bottle carries, or nothing.
//
// This is the step that makes a rebuild SELF-JUSTIFYING. Until now a bottle
// rebuilt for a security fix looked exactly like one rebuilt for any other
// reason: the version string said `_1` and nothing said why. The SBOM says
// what is inside, the provenance says how it was built, and this says which
// vulnerabilities were considered and what was decided about each.
//
// Three outcomes, and the middle one is the point:
//
//	no tree configured, or no file for this project → no referrer, no error
//	a file that exists and does not parse            → ERROR, nothing is published
//	a file that parses                               → the document
//
// A file that exists and cannot be read must not become a silent omission. The
// bottle would be published, look complete, and assert nothing — and the
// absence of a VEX document reads as "nothing was ever found", which is the
// opposite of what a broken record means.
func vexReferrer(dir, project, version, osn, arch string, tarball []byte, now time.Time) (*bottle.Referrer, error) {
	if dir == "" {
		return nil, nil
	}
	path := filepath.Join(dir, filepath.FromSlash(project), advisoryFile)
	b, err := osReadFile(path)
	if err != nil {
		// Absent is the normal case: most projects have never been triaged.
		// Any OTHER read error is not, and is reported.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("advisories: %w", err)
	}
	f, err := vuln.ParseAdvisories(b)
	if err != nil {
		return nil, err
	}
	// The same guard `bk advisories` applies, for the same reason: a file
	// copied from a neighbouring project would otherwise attach its findings
	// to this bottle, signed.
	if f.Project != project {
		return nil, fmt.Errorf("advisories: %s says project %q", path, f.Project)
	}
	sum := sha256.Sum256(tarball)
	dg := hex.EncodeToString(sum[:])
	purl := purlFor(project, version)
	doc, err := vuln.EncodeVEX(vuln.VEXOptions{
		ID:     vexDocumentID(project, version, osn, arch),
		Author: builderID,
		Role:   "Document Creator",
		// The SAME timestamp the SBOM and the provenance use, which honours
		// SOURCE_DATE_EPOCH — so re-publishing the same bottle produces a
		// byte-identical document, hence the same referrer digest, hence an
		// idempotent re-push rather than an accumulating pile.
		Timestamp: now,
		Version:   1,
		Tooling:   builderWithVersion(),
		Subjects: []vuln.Subject{{
			File: f,
			// Bound to the tarball DIGEST, the same anchor the SBOM, the
			// provenance and the cosign payload use. Four attestations about
			// one artefact, not four descriptions that happen to agree.
			// Version as well as the purl that already spells it: the encoder
			// decides from this field whether the record has anything to say
			// about THIS bottle, and a check that re-parsed the purl would be
			// a second spelling of the same fact (go-zpkg/bk#340).
			Products: []vuln.Product{{ID: purl, Version: version, PURL: purl, SHA256: dg}},
		}},
	})
	if err != nil {
		return nil, err
	}
	return &bottle.Referrer{ArtifactType: artifactOpenVEX, MediaType: artifactOpenVEX, Blob: doc}, nil
}

// checkAdvisories reads every record in a tree and returns how many projects
// have one, so a factory run refuses at the start rather than at a publish.
//
// It applies the same two checks `bk advisories` does — the file parses, and
// its `project:` agrees with its directory — because those are exactly the two
// that would stop a publish. An EMPTY tree is an error for the reason `bk
// advisories` makes it one: a run that was told where the records are and found
// none would otherwise publish every bottle with no document and look correct.
//
// An unset dir is not an error and reads nothing: attaching no document is the
// honest state for a factory that has no advisory tree.
func checkAdvisories(dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	paths, err := advisoryPaths(dir)
	if err != nil {
		return 0, fmt.Errorf("advisories: %w", err)
	}
	if len(paths) == 0 {
		return 0, fmt.Errorf("advisories: no %s under %s — the tree moved, or the wrong path was given", advisoryFile, dir)
	}
	for _, rel := range paths {
		p := filepath.Join(dir, filepath.FromSlash(rel), advisoryFile)
		b, err := osReadFile(p)
		if err != nil {
			return 0, fmt.Errorf("advisories: %w", err)
		}
		f, err := vuln.ParseAdvisories(b)
		if err != nil {
			return 0, fmt.Errorf("advisories: %s: %w", rel, err)
		}
		if f.Project != rel {
			return 0, fmt.Errorf("advisories: %s: the file says project %q", rel, f.Project)
		}
	}
	return len(paths), nil
}

// vexDocumentID is the document's IRI.
//
// It must be DETERMINISTIC — no timestamp, no counter — or a re-push of an
// unchanged bottle would produce a different document and a second referrer
// beside the first. It names the platform because two platforms' bottles are
// two artefacts, and a document asserting something about one must not claim
// to be the other.
func vexDocumentID(project, version, osn, arch string) string {
	return fmt.Sprintf("%s/vex/%s@%s--%s-%s", builderID, project, version, osn, arch)
}
