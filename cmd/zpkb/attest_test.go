package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
)

func attest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := runAttest(args, &out, &errb)
	return rc, out.String(), errb.String()
}

// withAttestations fakes what a registry holds for one artifact.
func withAttestations(t *testing.T, refs []artifact.Referrer, err error) *int {
	t.Helper()
	n := 0
	prev := attestFetch
	attestFetch = func(_, _, _, _, _ string) ([]artifact.Referrer, error) {
		n++
		return refs, err
	}
	t.Cleanup(func() { attestFetch = prev })
	return &n
}

// fourReferrers is what a signed artifact of a triaged project carries.
func fourReferrers() []artifact.Referrer {
	return []artifact.Referrer{
		{
			ArtifactType: artifactInToto, MediaType: artifactInToto,
			Blob: []byte(`{"predicate":{"runDetails":{"builder":{"id":"https://github.com/go-zpkg/zpkb@v0.26.0"}}}}`),
		},
		{
			ArtifactType: artifactOpenVEX, MediaType: artifactOpenVEX,
			Blob: []byte(`{"statements":[
				{"vulnerability":{"name":"MAL-2026-3020"},"status":"not_affected"},
				{"vulnerability":{"name":"CVE-2026-0001"},"status":"fixed"}]}`),
		},
		{
			ArtifactType: artifactCycloneDX, MediaType: artifactCycloneDX,
			Blob: []byte(`{"metadata":{"component":{"name":"bitwarden.com","version":"1.22.1","purl":"pkg:pkgx/bitwarden.com@1.22.1"}}}`),
		},
		{
			ArtifactType: artifact.ArtifactTypeSignature, MediaType: artifact.MediaSimpleSigning,
			Blob:        []byte(`{}`),
			Annotations: map[string]string{artifact.CosignSignatureAnnotation: "abc"},
		},
	}
}

func TestAttestListsWhatAArtifactCarries(t *testing.T) {
	withAttestations(t, fourReferrers(), nil)
	rc, out, errb := attest(t, "--platform", "linux/x86-64", "bitwarden.com", "1.22.1")
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, errb)
	}
	// The COUNT, and the platform it is about: a referrer list without a
	// platform beside it is a list for whichever one the host happens to be.
	if !strings.Contains(out, "bitwarden.com 1.22.1 linux/x86-64: 4 referrer(s)") {
		t.Errorf("want the header:\n%s", out)
	}
	for _, want := range []string{
		artifactCycloneDX, artifactInToto, artifactOpenVEX, artifact.ArtifactTypeSignature,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s is absent:\n%s", want, out)
		}
	}
	// ⛔ THE SUMMARY READS THE BLOB. A type says what a referrer claims to be;
	// only its body says whether it carries anything.
	for _, want := range []string{
		"2 statement(s): CVE-2026-0001=fixed MAL-2026-3020=not_affected",
		"pkg:pkgx/bitwarden.com@1.22.1",
		"https://github.com/go-zpkg/zpkb@v0.26.0",
		"signed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %q in:\n%s", want, out)
		}
	}
}

// Ordered by artifactType, so two runs over one artifact print the same thing: a
// registry does not promise an order, and a report whose lines move cannot be
// diffed.
func TestAttestOutputIsOrdered(t *testing.T) {
	refs := fourReferrers()
	withAttestations(t, refs, nil)
	_, out, _ := attest(t, "bitwarden.com", "1.22.1")
	ix := func(s string) int { return strings.Index(out, s) }
	// cyclonedx < in-toto < openvex < the signature type, alphabetically.
	if !(ix(artifactCycloneDX) < ix(artifactInToto) && ix(artifactInToto) < ix(artifactOpenVEX)) {
		t.Errorf("not ordered by artifactType:\n%s", out)
	}
	// And the caller's slice is not reordered under it.
	if refs[0].ArtifactType != artifactInToto {
		t.Errorf("the input was sorted in place: %s", refs[0].ArtifactType)
	}
}

// ⛔ ZERO IS A SENTENCE. An artifact with no referrers and an artifact this could not
// read about are the same silence otherwise.
func TestAttestSaysZeroOutLoud(t *testing.T) {
	withAttestations(t, nil, nil)
	rc, out, _ := attest(t, "lz4.org", "1.10.0")
	if rc != 0 {
		t.Fatalf("rc = %d — no referrers is not an error unless --require says so", rc)
	}
	if !strings.Contains(out, "0 referrer(s)") {
		t.Errorf("want the zero stated:\n%s", out)
	}
}

// --require turns the report into a gate, which is the whole point: a report is
// what you read after something went wrong, a gate is what tells you.
func TestAttestRequireIsAGate(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withAttestations(t, fourReferrers(), nil)
		rc, _, errb := attest(t, "--require", artifactOpenVEX+","+artifactInToto, "p", "1")
		if rc != 0 {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
	})
	t.Run("absent", func(t *testing.T) {
		// An artifact with everything BUT the document — which is exactly what a
		// lane that stopped passing --advisories produces.
		refs := fourReferrers()[:1]
		withAttestations(t, refs, nil)
		rc, _, errb := attest(t, "--require", artifactOpenVEX, "p", "1")
		if rc != 1 {
			t.Fatalf("rc = %d, want 1", rc)
		}
		if !strings.Contains(errb, "1 required artifactType(s) absent") || !strings.Contains(errb, artifactOpenVEX) {
			t.Errorf("want the missing type named: %q", errb)
		}
	})
	t.Run("several absent are all named", func(t *testing.T) {
		withAttestations(t, nil, nil)
		rc, _, errb := attest(t, "--require", artifactOpenVEX+","+artifactCycloneDX, "p", "1")
		if rc != 1 {
			t.Fatalf("rc = %d", rc)
		}
		if !strings.Contains(errb, "2 required") {
			t.Errorf("only one was named: %q", errb)
		}
	})
	t.Run("empty entries are ignored", func(t *testing.T) {
		// `--require ""` and a trailing comma are a shell's doing, not a
		// demand for an artifactType called "".
		withAttestations(t, fourReferrers(), nil)
		if rc, _, errb := attest(t, "--require", "", "p", "1"); rc != 0 {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
		if rc, _, errb := attest(t, "--require", artifactOpenVEX+",", "p", "1"); rc != 0 {
			t.Errorf("trailing comma: rc = %d, stderr = %q", rc, errb)
		}
	})
}

// A referrer whose type says OpenVEX and whose body says nothing is the
// failure this command exists to catch, and --require cannot see it: the type
// IS present. So the summary has to.
func TestAttestNamesAnEmptyOrUnreadableDocument(t *testing.T) {
	t.Run("no statements", func(t *testing.T) {
		withAttestations(t, []artifact.Referrer{{
			ArtifactType: artifactOpenVEX, Blob: []byte(`{"statements":[]}`),
		}}, nil)
		_, out, _ := attest(t, "p", "1")
		if !strings.Contains(out, "0 statement(s) — an empty document says nothing") {
			t.Errorf("want the emptiness named:\n%s", out)
		}
	})
	t.Run("not JSON", func(t *testing.T) {
		for _, typ := range []string{artifactOpenVEX, artifactCycloneDX, artifactInToto} {
			withAttestations(t, []artifact.Referrer{{ArtifactType: typ, Blob: []byte(`{nope`)}}, nil)
			_, out, _ := attest(t, "p", "1")
			if !strings.Contains(out, "unreadable") {
				t.Errorf("%s: want it called unreadable:\n%s", typ, out)
			}
		}
	})
	t.Run("a signature with no signature", func(t *testing.T) {
		withAttestations(t, []artifact.Referrer{{
			ArtifactType: artifact.ArtifactTypeSignature, Blob: []byte(`{}`),
		}}, nil)
		_, out, _ := attest(t, "p", "1")
		if !strings.Contains(out, "no signature in the annotation") {
			t.Errorf("want the empty annotation named:\n%s", out)
		}
	})
	t.Run("a type this command does not know", func(t *testing.T) {
		// Reported with no summary rather than refused: a new attestation
		// kind must not make this command fail.
		withAttestations(t, []artifact.Referrer{{ArtifactType: "application/vnd.invented", Blob: []byte("x")}}, nil)
		rc, out, _ := attest(t, "p", "1")
		if rc != 0 || !strings.Contains(out, "application/vnd.invented") {
			t.Errorf("rc = %d, out = %q", rc, out)
		}
	})
}

func TestAttestRefusals(t *testing.T) {
	t.Run("the registry cannot be read", func(t *testing.T) {
		withAttestations(t, nil, errors.New("404 manifest unknown"))
		rc, _, errb := attest(t, "p", "1")
		if rc != 1 || !strings.Contains(errb, "404 manifest unknown") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
		// And it names WHICH artifact, because a 404 without one is a 404
		// about nothing.
		if !strings.Contains(errb, "p 1") {
			t.Errorf("the artifact is not named: %q", errb)
		}
	})
	t.Run("a bad platform", func(t *testing.T) {
		rc, _, errb := attest(t, "--platform", "linux", "p", "1")
		if rc != 2 || !strings.Contains(errb, "bad --platform") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
	})
	t.Run("too few arguments", func(t *testing.T) {
		rc, _, errb := attest(t, "p")
		if rc != 2 || !strings.Contains(errb, "usage: bk attest") {
			t.Errorf("rc = %d, stderr = %q", rc, errb)
		}
	})
	t.Run("too many arguments", func(t *testing.T) {
		if rc, _, _ := attest(t, "p", "1", "2"); rc != 2 {
			t.Error("a third argument must be a usage error")
		}
	})
	t.Run("an unknown flag", func(t *testing.T) {
		if rc, _, _ := attest(t, "--nonesuch"); rc != 2 {
			t.Error("an unknown flag must be a usage error")
		}
	})
}

// With no --platform it reads THIS host's, so a person checking an artifact on
// their own machine gets the one they would install.
func TestAttestDefaultsToThisHost(t *testing.T) {
	withAttestations(t, nil, nil)
	_, out, _ := attest(t, "p", "1")
	osn, arch := artifact.HostSlug()
	if !strings.Contains(out, osn+"/"+arch) {
		t.Errorf("want this host's platform %s/%s in:\n%s", osn, arch, out)
	}
}

// Through the top-level dispatch, which is the only thing a CI lane invokes.
func TestAttestDispatch(t *testing.T) {
	withAttestations(t, fourReferrers(), nil)
	var out, errb bytes.Buffer
	if code := run([]string{"attest", "--platform", "linux/x86-64", "p", "1"}, &out, &errb); code != 0 {
		t.Errorf("code = %d, stderr = %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "4 referrer(s)") {
		t.Errorf("want the totals on stdout, got %q", out.String())
	}
}

// TestAttestSeamReachesTheRegistry exercises the DEFAULT seam — the code every
// test above replaces — the way TestSourceSeamsReachTheRegistry does for its
// sibling, rather than inventing a second shape for the same need.
//
// Both branches, and neither needs a network: a base that is not an oci:// ref
// cannot build a client at all, and one that is well-formed but unreachable
// makes the call and fails. A seam whose real body no test enters is a body
// nobody has compiled against the library it calls.
func TestAttestSeamReachesTheRegistry(t *testing.T) {
	t.Setenv("ZPKG_VERIFY", "0")
	if _, err := attestFetch("not-an-oci-ref", "p", "1", "darwin", "aarch64"); err == nil {
		t.Error("a base that is not an oci:// ref built a client")
	}
	if _, err := attestFetch("oci://127.0.0.1:1/x", "p", "1", "darwin", "aarch64"); err == nil {
		t.Error("an unreachable registry answered")
	}
}
