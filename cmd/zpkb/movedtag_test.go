package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func digestOfBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// withPublishedDigest points the registry seam at one answer.
func withPublishedDigest(t *testing.T, digest string, err error) {
	t.Helper()
	old := ociArtifactDigest
	ociArtifactDigest = func(_, _, _, _, _ string) (string, error) { return digest, err }
	t.Cleanup(func() { ociArtifactDigest = old })
}

// aSpec is a non-zero identity, so the tag under test is a HASHED one.
func aSpec() artifact.Concrete {
	return artifact.Concrete{Platform: "linux/x86-64", Recipe: "sha256:abc"}
}

// ⛔⛔ THE WITNESS. A build's identity excludes the builder on purpose, so a
// zpkb whose output differs lands on the SAME hashed tag with DIFFERENT bytes.
// Before this guard that push went through and silently rewrote what every
// existing lock, install and signature refers to.
func TestRefusesToMoveAHashedTag(t *testing.T) {
	mine := []byte("the bytes this build produced")
	theirs := []byte("the bytes already published there")
	withPublishedDigest(t, digestOfBytes(theirs), nil)

	o := publishOptions{Dist: "oci://x", Project: "fftw.org", Version: "3.3.11",
		OS: "linux", Arch: "x86-64", Concrete: aSpec()}
	err := refuseToMoveATag(o, "3.3.11-habcdefghijklmnop", mine)
	if err == nil {
		t.Fatal("a push that changes what a hashed tag resolves to was allowed")
	}
	// ⛔ BOTH DIGESTS, OR THE REFUSAL IS NOT ACTIONABLE. "they differ" is the
	// start of an investigation; the two values are what a report carries.
	for _, want := range []string{digestOfBytes(theirs), digestOfBytes(mine), "zpkb#416"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}
}

// ⛔ RE-PUBLISHING THE SAME BYTES IS THE NORMAL CASE AND MUST STAY SILENT. A
// retried run and a re-dispatch both land here; a guard that refused them
// would turn idempotence into a failure.
func TestAllowsRepublishingIdenticalBytes(t *testing.T) {
	same := []byte("identical")
	withPublishedDigest(t, digestOfBytes(same), nil)
	o := publishOptions{Project: "p", Version: "1", OS: "linux", Arch: "x86-64", Concrete: aSpec()}
	if err := refuseToMoveATag(o, "1-habcdefghijklmnop", same); err != nil {
		t.Errorf("an idempotent re-push was refused: %v", err)
	}
}

// ⛔⛔ NOT KNOWING IS NEVER A REFUSAL. An unreachable registry, a tag that does
// not exist, a manifest with no layer: all mean "nothing contradicts this
// push". A factory that halted a campaign over a network blip would be a
// worse defect than the one this guards.
func TestNotKnowingDoesNotRefuse(t *testing.T) {
	o := publishOptions{Project: "p", Version: "1", OS: "linux", Arch: "x86-64", Concrete: aSpec()}
	body := []byte("x")

	withPublishedDigest(t, "", errRegistryUnreachable{})
	if err := refuseToMoveATag(o, "1-habcdefghijklmnop", body); err != nil {
		t.Errorf("an unreachable registry refused the push: %v", err)
	}
	withPublishedDigest(t, "", nil) // no such tag yet
	if err := refuseToMoveATag(o, "1-habcdefghijklmnop", body); err != nil {
		t.Errorf("a first publish was refused: %v", err)
	}

	// And an artifact with NO identity lands on the bare version, which has
	// always been a moving tag — `bk publish` of something this process did
	// not build cannot know what it is.
	plain := publishOptions{Project: "p", Version: "1", OS: "linux", Arch: "x86-64"}
	withPublishedDigest(t, digestOfBytes([]byte("something else")), nil)
	if err := refuseToMoveATag(plain, "1", body); err != nil {
		t.Errorf("an unidentified artifact was held to a hashed tag's rule: %v", err)
	}
}

// ⛔ AND publishArtifact ACTUALLY STOPS. refuseToMoveATag returning an error is
// worth nothing if the caller pushes anyway, so this drives the real publish
// path and asserts that NOTHING reached the registry.
func TestPublishArtifactStopsBeforeMovingATag(t *testing.T) {
	pushed := false
	oldPush := ociPush
	ociPush = func(_, _, _, _, _ string, _ []byte, _ string, _ []artifact.Referrer, _ map[string]string) (ocispec.Descriptor, error) {
		pushed = true
		return ocispec.Descriptor{}, nil
	}
	t.Cleanup(func() { ociPush = oldPush })

	body := []byte("this build's bytes")
	p := filepath.Join(t.TempDir(), "v1.0.0"+artifact.ExtTarGz)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	withPublishedDigest(t, digestOfBytes([]byte("somebody else's bytes")), nil)

	_, _, err := publishArtifact(publishOptions{
		Dist: "oci://example.invalid/x", Project: "acme.org/tool", Version: "1.0.0",
		OS: "linux", Arch: "aarch64", Path: p, Concrete: aSpec(),
	})
	if err == nil {
		t.Fatal("publishArtifact pushed over a hashed tag holding other bytes")
	}
	if pushed {
		t.Error("the refusal was reported AND the push happened anyway")
	}
	if !strings.Contains(err.Error(), "refusing to move") {
		t.Errorf("unexpected error: %v", err)
	}
}

type errRegistryUnreachable struct{}

func (errRegistryUnreachable) Error() string { return "dial tcp: connection refused" }

// The skip message names the factory that made the artifact already there, so a
// skip a human cannot act on becomes one they can.
func TestStaleBuilderNote(t *testing.T) {
	old := factoryPublishedBuilder
	t.Cleanup(func() { factoryPublishedBuilder = old })

	factoryPublishedBuilder = func(_, _, _, _, _ string) (string, error) {
		return "https://github.com/go-pkgx/bk@v0.26.0", nil
	}
	note := staleBuilderNote("oci://x", "p", "1-habc", "linux", "x86-64")
	for _, want := range []string{"go-pkgx/bk@v0.26.0", builderWithVersion(), "force", "zpkb#416"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note should mention %q: %q", want, note)
		}
	}

	// ⛔ SILENT WHEN THE COMPARISON CANNOT BE MADE, and silent when it agrees.
	// Three ways of not knowing, one way of knowing there is nothing to say.
	factoryPublishedBuilder = func(_, _, _, _, _ string) (string, error) { return builderWithVersion(), nil }
	if got := staleBuilderNote("oci://x", "p", "1-habc", "linux", "x86-64"); got != "" {
		t.Errorf("the same builder produced a note: %q", got)
	}
	factoryPublishedBuilder = func(_, _, _, _, _ string) (string, error) { return "", nil }
	if got := staleBuilderNote("oci://x", "p", "1-habc", "linux", "x86-64"); got != "" {
		t.Errorf("an unrecorded builder produced a note: %q", got)
	}
	factoryPublishedBuilder = func(_, _, _, _, _ string) (string, error) {
		return "", errRegistryUnreachable{}
	}
	if got := staleBuilderNote("oci://x", "p", "1-habc", "linux", "x86-64"); got != "" {
		t.Errorf("an unreachable registry produced a note: %q", got)
	}
}

// The seam's real body is exercised too: a seam that only ever runs its test
// double is code nobody has executed.
func TestFactoryPublishedBuilderSeam(t *testing.T) {
	if _, err := factoryPublishedBuilder("https://not-oci", "p", "1", "linux", "x86-64"); err == nil {
		t.Error("a non-oci dist was accepted")
	}
	if _, err := factoryPublishedBuilder("oci://127.0.0.1:1/nothing", "p", "1", "linux", "x86-64"); err == nil {
		t.Error("a dead registry reported success")
	}
}
