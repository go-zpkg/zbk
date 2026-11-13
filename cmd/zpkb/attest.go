package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-zpkg/bottle"
)

// runAttest says what a PUBLISHED bottle carries, and can fail when something
// expected is missing.
//
// # WHY THIS EXISTS
//
// Four kinds of thing are attached to a bottle as OCI referrers — a CycloneDX
// SBOM, an in-toto SLSA provenance, a cosign signature, and (since bk v0.24.0)
// an OpenVEX document. Nothing could be asked which of them a given bottle
// actually has.
//
// That gap is not academic. `bk publish --advisories` attaches the VEX
// document only when the advisory tree holds a record for the project, and the
// factory passes the tree through six lanes, one of which mounts it into a
// chroot. Every one of those is a place where the document can silently fail to
// appear — and a bottle with no document looks exactly like a bottle nobody
// had anything to say about. `bk source` reads the provenance and `bk buildenv`
// reads it too, but neither ENUMERATES, so "did it land?" had no answer but
// curl against the referrers API.
//
// # WHY IT CAN FAIL
//
// --require turns the report into a gate. A report is what you read after
// something went wrong; a gate is what tells you. The factory's own lanes can
// end with
//
//	bk attest --require application/vnd.openvex+json <project> <version>
//
// and a lane that stopped attaching documents goes red instead of quiet.
func runAttest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", bottle.DistBase, "oci:// registry to read")
	platform := fs.String("platform", "", "bottle os/arch, e.g. linux/x86-64 (default: this host's)")
	require := fs.String("require", "", "comma-separated artifactTypes that MUST be present; exit non-zero if one is not")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: bk attest [--dist oci://…] [--platform os/arch] [--require type,…] <project> <version>")
		return 2
	}
	project, ver := fs.Arg(0), fs.Arg(1)

	osn, arch, ok := attestPlatform(*platform)
	if !ok {
		fmt.Fprintf(stderr, "attest: bad --platform %q (want os/arch)\n", *platform)
		return 2
	}

	refs, err := attestFetch(*dist, project, ver, osn, arch)
	if err != nil {
		fmt.Fprintf(stderr, "attest: %s %s (%s/%s): %v\n", project, ver, osn, arch, err)
		return 1
	}

	// ⛔ THE COUNT FIRST, AND ZERO IS A SENTENCE. A bottle with no referrers
	// and a bottle this could not read about are the same silence otherwise,
	// and this fleet has published a zero that meant "could not read".
	fmt.Fprintf(stdout, "%s %s %s/%s: %d referrer(s)\n", project, ver, osn, arch, len(refs))
	present := map[string]bool{}
	for _, r := range sortReferrers(refs) {
		present[r.ArtifactType] = true
		fmt.Fprintf(stdout, "  %-34s %7d bytes  %s\n", r.ArtifactType, len(r.Blob), summariseReferrer(r))
	}

	var missing []string
	for _, want := range strings.Split(*require, ",") {
		if want = strings.TrimSpace(want); want == "" {
			continue
		}
		if !present[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "attest: %d required artifactType(s) absent: %s\n",
			len(missing), strings.Join(missing, ", "))
		return 1
	}
	return 0
}

// attestPlatform resolves the platform to read, defaulting to this host's.
func attestPlatform(spec string) (string, string, bool) {
	if spec == "" {
		osn, arch := bottle.HostSlug()
		return osn, arch, true
	}
	return splitPlatform(spec)
}

// attestFetch is the seam: the tests drive the whole command without a
// registry.
var attestFetch = func(dist, project, ver, osn, arch string) ([]bottle.Referrer, error) {
	c, err := bottle.NewOCIClient(dist)
	if err != nil {
		return nil, err
	}
	refs, _, err := c.FetchAttestations(project, ver, osn, arch)
	return refs, err
}

// sortReferrers orders by artifactType so two runs over one bottle print the
// same thing. A registry does not promise an order, and a report whose lines
// move between runs cannot be diffed.
func sortReferrers(refs []bottle.Referrer) []bottle.Referrer {
	out := make([]bottle.Referrer, len(refs))
	copy(out, refs)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ArtifactType < out[j].ArtifactType })
	return out
}

// summariseReferrer says the one thing worth knowing about each kind, from its blob.
//
// It reads the blob rather than trusting the artifactType: a referrer whose
// type says OpenVEX and whose body is empty is the failure this command exists
// to catch, and "0 statement(s)" says so where a byte count would not.
func summariseReferrer(r bottle.Referrer) string {
	switch r.ArtifactType {
	case artifactOpenVEX:
		var doc struct {
			Statements []struct {
				Status        string `json:"status"`
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
			} `json:"statements"`
		}
		if err := json.Unmarshal(r.Blob, &doc); err != nil {
			return "unreadable: " + err.Error()
		}
		if len(doc.Statements) == 0 {
			return "0 statement(s) — an empty document says nothing"
		}
		var parts []string
		for _, s := range doc.Statements {
			parts = append(parts, s.Vulnerability.Name+"="+s.Status)
		}
		sort.Strings(parts)
		return fmt.Sprintf("%d statement(s): %s", len(doc.Statements), strings.Join(parts, " "))
	case artifactCycloneDX:
		var doc struct {
			Metadata struct {
				Component struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Purl    string `json:"purl"`
				} `json:"component"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(r.Blob, &doc); err != nil {
			return "unreadable: " + err.Error()
		}
		return doc.Metadata.Component.Purl
	case artifactInToto:
		var doc struct {
			Predicate struct {
				RunDetails struct {
					Builder struct {
						ID string `json:"id"`
					} `json:"builder"`
				} `json:"runDetails"`
			} `json:"predicate"`
		}
		if err := json.Unmarshal(r.Blob, &doc); err != nil {
			return "unreadable: " + err.Error()
		}
		return doc.Predicate.RunDetails.Builder.ID
	case bottle.ArtifactTypeSignature:
		// The signature itself lives in an annotation, not the blob, so its
		// presence is the thing to report.
		if r.Annotations[bottle.CosignSignatureAnnotation] == "" {
			return "no signature in the annotation"
		}
		return "signed"
	}
	return ""
}
