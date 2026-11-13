package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"

	"github.com/go-zpkg/bottle"
)

// runSign implements `zpkb sign`: a SECOND builder's word on a bottle somebody
// else published.
//
// ⛔⛔ THE WHOLE POINT IS THAT IT DOES NOT PUBLISH ANYTHING. Two people who
// build the same inputs get the same identity — deliberately, because an
// identity that varied with the builder could never be compared. So the
// artefact stays one artefact, and what differs is the ATTESTATION: each
// builder attaches their own signature referrer to the one bottle, and a
// client counts how many distinct trusted keys it can verify
// (ZPKG_TRUST_THRESHOLD).
//
// This is the publishing half of what `zpkb reproduce` already does locally.
// The sequence a rebuilder follows:
//
//	zpkb build …                     # your own build, your own machine
//	zpkb reproduce yours.tar.gz theirs.tar.gz
//	zpkb sign -key you.sec -project … -version … yours.tar.gz
//
// ⛔ AND IT REFUSES WHEN THE DIGESTS DIFFER, WHICH IS THE INTERESTING CASE.
// Guix's `guix challenge` exists to report exactly that, and the report is
// the finding: a divergence means the recipe is not reproducible, or one of
// the two machines is not what it claims. Signing anyway would convert a
// finding into a second signature on a bottle this build did NOT produce,
// which is the one thing the threshold must never be able to say.
func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "secret key file to sign with (go-attest/sign format)")
	project := fs.String("project", "", "pkgx project slug, e.g. fftw.org")
	version := fs.String("version", "", "published version TAG, including any -h<hash> suffix")
	osn := fs.String("os", "", "pkgx-form OS of the published bottle (default: this host's)")
	arch := fs.String("arch", "", "pkgx-form architecture (default: this host's)")
	to := fs.String("to", bottle.DistBase, "oci:// registry holding the bottle")
	force := fs.Bool("force", false,
		"sign even though the rebuild's digest differs from the published one. ⛔ THIS SIGNS BYTES YOU DID NOT PRODUCE: a divergence is a FINDING about reproducibility, and this flag converts it into a claim that two builders agree when they do not")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *key == "" || *project == "" || *version == "" {
		fmt.Fprintln(stderr, "usage: zpkb sign -key <secret> -project <slug> -version <tag> [-os o -arch a] [-to oci://…] <rebuilt-bottle>")
		fmt.Fprintln(stderr, "  Attaches YOUR signature to an already-published bottle, after checking that")
		fmt.Fprintln(stderr, "  your rebuild produced the same bytes. It never pushes a bottle.")
		return 2
	}
	o, a := *osn, *arch
	if o == "" || a == "" {
		ho, ha := bottle.HostSlug()
		if o == "" {
			o = ho
		}
		if a == "" {
			a = ha
		}
	}

	kp, err := loadSigningKey(*key)
	if err != nil {
		fmt.Fprintln(stderr, "zpkb sign:", err)
		return 1
	}
	rebuilt, err := osReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "zpkb sign:", err)
		return 1
	}
	sum := sha256.Sum256(rebuilt)
	mine := "sha256:" + hex.EncodeToString(sum[:])

	published, err := ociBottleDigest(*to, *project, *version, o, a)
	if err != nil {
		fmt.Fprintln(stderr, "zpkb sign:", err)
		return 1
	}
	if published != mine {
		// ⛔ BOTH DIGESTS, ALWAYS. "They differ" is not a finding anybody can
		// act on; the two values are what a report carries, and what the
		// next person compares against their own.
		fmt.Fprintf(stderr, "zpkb sign: your rebuild is NOT the published bottle\n")
		fmt.Fprintf(stderr, "  published: %s\n", published)
		fmt.Fprintf(stderr, "  yours:     %s\n", mine)
		fmt.Fprintf(stderr, "  `zpkb reproduce` says what differs. Signing anyway needs -force, and\n")
		fmt.Fprintf(stderr, "  would claim two builders agree when they do not.\n")
		if !*force {
			return 1
		}
		fmt.Fprintln(stderr, "  -force given: signing the PUBLISHED bytes regardless")
	}

	// ⛔ THE PURL IS NOT WHAT A VERIFIER COMPARES, which is why this can move
	// without re-signing the corpus. bottle's payloadCommitsTo (verify.go:185)
	// reads ONLY `critical.image.docker-manifest-digest`; the identity is
	// never looked at. A bottle signed with the retired `pkg:pkgx/` purl still
	// verifies, because the digest it commits to has not changed.
	payload, err := simpleSigning(purlFor(*project, *version), published)
	if err != nil {
		fmt.Fprintln(stderr, "zpkb sign:", err)
		return 1
	}
	if err := ociAttach(*to, *project, *version, o, a, signatureReferrer(payload, kp)); err != nil {
		fmt.Fprintln(stderr, "zpkb sign:", err)
		return 1
	}
	fmt.Fprintf(stdout, "signed %s %s (%s/%s) %s with key %s\n",
		*project, *version, o, a, published, hex.EncodeToString(kp.ID[:]))
	fmt.Fprintf(stdout, "add it to a client's trust set with:\n  ZPKG_EXTRA_TRUSTED_KEYS='<name>:%s'\n", kp.PublicKeyString())
	return 0
}

// Seams, like ociPush, so tests drive the command without a registry.
var (
	ociBottleDigest = func(distBase, project, ver, osn, arch string) (string, error) {
		c, err := bottle.NewOCIClient(distBase)
		if err != nil {
			return "", err
		}
		return c.BottleDigest(project, ver, osn, arch)
	}
	ociAttach = func(distBase, project, ver, osn, arch string, rf bottle.Referrer) error {
		c, err := bottle.NewOCIClient(distBase)
		if err != nil {
			return err
		}
		return c.AttachReferrer(project, ver, osn, arch, rf)
	}
)
