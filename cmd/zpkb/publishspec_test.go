package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// pushCapture replaces the OCI push and records the tag and annotations a
// publish would have written.
func pushCapture(t *testing.T) (*string, *map[string]string) {
	t.Helper()
	var tag string
	var ann map[string]string
	old := ociPush
	t.Cleanup(func() { ociPush = old })
	ociPush = func(_, _, tg, _, _ string, _ []byte, _ string, _ []artifact.Referrer, a map[string]string) (ocispec.Descriptor, error) {
		tag, ann = tg, a
		return ocispec.Descriptor{}, nil
	}
	return &tag, &ann
}

// emptyArtifact writes an artifact with nothing interesting in it, so these tests
// are about the tag and the annotation and not about the payload.
func emptyArtifact(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "v1.0.0"+artifact.ExtTarGz)
	if err := os.WriteFile(p, gzBytes(tarBytes(map[string][]byte{"share/doc/x": []byte("x")})), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func specOfTool() artifact.Concrete {
	return artifact.Concrete{
		Platform: "linux/aarch64",
		Recipe:   "sha256:0123456789abcdef",
		Deps: []artifact.Dep{
			{Project: "openssl.org", Version: "3.6.4", Hash: "abcdefghijklmnop"},
		},
	}
}

// ⛔⛔ THE TAG AND THE ANNOTATION ARE PUBLISHED AS A PAIR, AND A READER CHECKS
// ONE AGAINST THE OTHER. artifact.VerifySpec recomputes the hash from the spec
// on the manifest and compares it with the hash in the tag; a publisher that
// wrote one without the other, or wrote a hash from a different computation,
// would produce artifacts that fail their own verification with a message —
// "the artifact does not match its own description" — that reads as tampering.
//
// So this test is the reader, not the writer: it does what `artifact.SpecOf`
// does, on what the publish path actually pushed.
func TestAPublishedArtifactVerifiesAgainstItsOwnTag(t *testing.T) {
	tag, ann := pushCapture(t)
	spec := specOfTool()

	if _, _, err := publishArtifact(publishOptions{
		Dist: "oci://example.invalid/x", Project: "acme.org/tool", Version: "1.0.0",
		OS: "linux", Arch: "aarch64", Path: emptyArtifact(t), Concrete: spec,
	}); err != nil {
		t.Fatal(err)
	}

	version, hash := artifact.SplitVariantHash(*tag)
	if version != "1.0.0" {
		t.Errorf("the version is not readable out of the tag %q: got %q", *tag, version)
	}
	if hash == "" {
		t.Fatalf("the tag %q carries no identity, so two builds of 1.0.0 would collide on it", *tag)
	}
	got, err := artifact.VerifySpec(artifact.Annotation(*ann, artifact.SpecAnnotation), hash)
	if err != nil {
		t.Fatalf("the artifact does not verify against its own tag: %v", err)
	}
	if got.Platform != spec.Platform || len(got.Deps) != len(spec.Deps) {
		t.Errorf("the spec came back changed: %+v", got)
	}
}

// ⛔ THE SPEC MUST NOT BE DROPPED BY ANOTHER ANNOTATION. Each of the glibc and
// ABI branches used to build a FRESH map, which was harmless while the spec
// did not exist and would now silently delete it — leaving a tag that claims
// a hash and a manifest that cannot say what the hash is of. That artifact is
// worse than one with neither, because VerifySpec reads the missing half as
// an artifact that lies about itself.
func TestTheSpecSurvivesEveryOtherAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  publishOptions
		alsoK string
	}{
		{"a glibc-flavoured tool", publishOptions{Glibc: "=2.27.0"}, artifact.GlibcVersionAnnotation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag, ann := pushCapture(t)
			o := tc.opts
			o.Dist, o.Project, o.Version = "oci://example.invalid/x", "acme.org/tool", "1.0.0"
			o.OS, o.Arch, o.Path, o.Concrete = "linux", "aarch64", emptyArtifact(t), specOfTool()
			if _, _, err := publishArtifact(o); err != nil {
				t.Fatal(err)
			}
			if (*ann)[tc.alsoK] == "" {
				t.Errorf("the other annotation %s is missing: %v", tc.alsoK, *ann)
			}
			_, hash := artifact.SplitVariantHash(*tag)
			if _, err := artifact.VerifySpec(artifact.Annotation(*ann, artifact.SpecAnnotation), hash); err != nil {
				t.Fatalf("the spec did not survive: %v (annotations: %v)", err, *ann)
			}
			// And the readable flavour is still in the tag, before the hash.
			if !strings.Contains(*tag, "-glibc2.27.0-h") {
				t.Errorf("tag = %q, want the flavour then the identity", *tag)
			}
		})
	}
}

// ⛔⛔ A ARTIFACT WE DID NOT BUILD GETS NO ADDRESS AND NO DESCRIPTION. `bk
// publish` on a mirrored tarball knows nothing about how it was made, and a
// tag carrying a hash would be a claim that we do. The honest shape is the
// bare version — distinguishable, by a reader, from a build whose spec we
// hold, which is exactly what artifact.SpecOf reports as "no spec" rather than
// as an error.
func TestAMirroredArtifactIsPublishedWithoutAnIdentityItDoesNotHave(t *testing.T) {
	tag, ann := pushCapture(t)
	if _, _, err := publishArtifact(publishOptions{
		Dist: "oci://example.invalid/x", Project: "acme.org/tool", Version: "1.0.0",
		OS: "linux", Arch: "aarch64", Path: emptyArtifact(t),
	}); err != nil {
		t.Fatal(err)
	}
	if *tag != "1.0.0" {
		t.Errorf("tag = %q, want the bare version for an artifact we cannot describe", *tag)
	}
	if _, present := artifact.AnnotationPresent(*ann, artifact.SpecAnnotation); present {
		t.Errorf("an artifact we know nothing about described itself: %v", *ann)
	}
}
