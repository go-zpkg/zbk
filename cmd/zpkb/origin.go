package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/go-zpkg/artifact"
)

// runOrigin implements `bk origin`: what a published artifact says about HOW it
// was built, and whether that is enough to promote it.
//
// ⛔ THE QUESTION IT ANSWERS COULD NOT BE ASKED. go-zpkg/packages#316 needs the
// s390x toolchain to reach ghcr. Generations 0 and 1 both publish only to a
// throwaway loopback registry on the LinuxONE VM — deliberately, because
// artifacts driven by the host's compiler must not reach the real registry — so
// promoting anything out of there needs one fact per artifact: was the host's
// toolchain involved. Measured 2026-11-01, the registry could not say:
//
//	$ bk buildenv -platform linux/s390x lz4.org 1.10.0
//	buildenv: lz4.org 1.10.0 (linux/s390x): the provenance records no build
//	environment
//
// An empty build environment is what a bootstrap build produces, since it
// resolves no artifacts. It is ALSO what an older bk produced, and what a
// mirrored artifact produces. Three situations, one silence — and a gate cannot
// read a silence.
//
// ⛔ SO `-promotable` REQUIRES AN EXPLICIT "0" AND TREATS EVERY OTHER ANSWER AS
// NO. Not because unknown artifacts are suspect, but because the failure
// directions are not symmetric: refusing to promote a good artifact costs a
// rebuild, and promoting a host-built one puts an unpinned Ubuntu compiler's
// output in the production registry under our signature. The default answer
// to "may I?" is no.
func runOrigin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("origin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", artifact.DistBase, "the registry the artifact was published to")
	platform := fs.String("platform", "", "os/arch to read, e.g. linux/s390x (default: this machine)")
	promotable := fs.Bool("promotable", false, "say nothing and exit 0 only if the provenance PROVES the host toolchain was not used; exit 1 otherwise, including when nothing is recorded")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: zpkb origin [--dist d] [--platform os/arch] [--promotable] <project> <version>")
		return 2
	}
	project, version := fs.Arg(0), fs.Arg(1)

	osn, arch, err := buildEnvPlatform(*platform)
	if err != nil {
		fmt.Fprintln(stderr, "origin:", err)
		return 2
	}
	refs, err := sourceAttestations(*dist, project, version, osn, arch)
	if err != nil {
		fmt.Fprintf(stderr, "origin: %s %s (%s/%s): %v\n", project, version, osn, arch, err)
		return 1
	}
	o, err := originAttestedBy(refs)
	if err != nil {
		// Reported as a refusal under -promotable and as a fact otherwise: the
		// absence is the honest state of every artifact published before this
		// existed, and a sweep that called those broken would condemn the
		// whole registry.
		fmt.Fprintf(stderr, "origin: %s %s (%s/%s): %v\n", project, version, osn, arch, err)
		return 1
	}

	if *promotable {
		if o.Bootstrap != "0" {
			fmt.Fprintf(stderr, "origin: %s %s (%s/%s) is NOT promotable: %s\n",
				project, version, osn, arch, o.why())
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "%s %s %s/%s\n", project, version, osn, arch)
	fmt.Fprintf(stdout, "  host toolchain used: %s\n", o.bootstrapWords())
	if o.Dist == "" {
		fmt.Fprintln(stdout, "  inputs resolved from: not recorded")
	} else {
		fmt.Fprintf(stdout, "  inputs resolved from: %s\n", o.Dist)
	}
	return 0
}

// why says, in one clause, what stands between this artifact and promotion.
func (o provOrigin) why() string {
	switch o.Bootstrap {
	case "1":
		return "it was built with --bootstrap, so its compiler and shell came from the host distribution rather than from artifacts"
	case "":
		return "its provenance does not say whether the host toolchain was used, and an unstated answer is not a \"no\""
	default:
		return "its provenance records bootstrap=" + o.Bootstrap + ", which is neither 0 nor 1"
	}
}

// bootstrapWords renders the tri-state for a reader rather than a script.
func (o provOrigin) bootstrapWords() string {
	switch o.Bootstrap {
	case "1":
		return "yes — built with --bootstrap, NOT promotable"
	case "0":
		return "no — built from artifacts"
	case "":
		return "not recorded"
	default:
		return "unreadable value " + o.Bootstrap
	}
}

// originAttestedBy reads the origin a published artifact records.
//
// "Nothing recorded" is an error and not a zero value, for the same reason
// envAttestedBy makes that distinction: the caller must not be able to forget
// which it got.
func originAttestedBy(refs []artifact.Referrer) (provOrigin, error) {
	var raw []byte
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			raw = r.Blob
			break
		}
	}
	if raw == nil {
		return provOrigin{}, errNoProvenance
	}
	var stmt struct {
		Predicate struct {
			BuildDefinition struct {
				ExternalParameters map[string]string `json:"externalParameters"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return provOrigin{}, fmt.Errorf("provenance: %w", err)
	}
	p := stmt.Predicate.BuildDefinition.ExternalParameters
	o := provOrigin{Bootstrap: p["bootstrap"], Dist: p["inputs-from"]}
	if o.Bootstrap == "" && o.Dist == "" {
		return o, errNoOrigin
	}
	return o, nil
}

// errNoOrigin is the state of every artifact published before `bk origin`
// existed: a provenance that is present, valid, and silent on this question.
var errNoOrigin = fmt.Errorf("the provenance records no build origin (published before zpkb recorded one)")

// promotableOrigin is the gate `--require-origin` applies, as a method so the
// factory's mirror path and `bk origin --promotable` cannot drift apart: one
// reading of the provenance, one rule about what it has to say.
//
// ⛔ IT RETURNS AN ERROR AND NOT A BOOL. A bool would have let the caller
// write `if ok { … }` and carry on when the registry was simply unreachable —
// and "I could not ask" must not land in the same branch as "the answer was
// no". The caller fails the project with the reason, so the run's own log
// says which of the two happened.
func (f *factory) promotableOrigin(proj, tag string) (provOrigin, error) {
	refs, err := sourceAttestations(f.mirror, proj, tag, f.osn, f.arch)
	if err != nil {
		return provOrigin{}, fmt.Errorf("cannot read the source provenance from %s: %w", f.mirror, err)
	}
	o, err := originAttestedBy(refs)
	if err != nil {
		return provOrigin{}, err
	}
	if o.Bootstrap != "0" {
		return provOrigin{}, fmt.Errorf("not promotable: %s", o.why())
	}
	return o, nil
}
