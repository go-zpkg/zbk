package main

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/moustache"
)

// decodeProv pulls the in-toto statement out of the referrers and reads it as
// the wire shape a consumer sees, not as the struct we happened to build.
func decodeProv(t *testing.T, refs []artifact.Referrer) map[string]any {
	t.Helper()
	for _, r := range refs {
		if r.ArtifactType != artifactInToto {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(r.Blob, &m); err != nil {
			t.Fatalf("the provenance is not JSON: %v", err)
		}
		return m
	}
	t.Fatal("no in-toto referrer was produced")
	return nil
}

// ⛔⛔ A BUILDER THAT NEVER CHANGES CANNOT TELL TWO BUILDS APART.
//
// Measured 2026-10-09 on the published stedolan.github.io/jq: its signed SLSA
// statement carries
//
//	"builder": { "id": "https://github.com/go-zpkg/zpkb" }
//	"buildDefinition": { "externalParameters": {}, "internalParameters": {} }
//
// — the same two constants every artifact in the registry carries. So "which bk
// built this, and for what?" had no answer in the artefact, and a rebuild for
// a toolchain security fix was indistinguishable from the build before it.
func TestTheProvenanceSaysWhichBkAndWhatItWasAsked(t *testing.T) {
	refs, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "aarch64",
		[]byte("tarball"), build.SourceRef{}, nil, time.Unix(0, 0).UTC(), nil, provOrigin{})
	if err != nil {
		t.Fatal(err)
	}
	m := decodeProv(t, refs)

	pred, _ := m["predicate"].(map[string]any)
	run, _ := pred["runDetails"].(map[string]any)
	b, _ := run["builder"].(map[string]any)
	id, _ := b["id"].(string)

	// ⛔ THE REGRESSION: the bare constant, with nothing after it.
	if id == builderID {
		t.Errorf("builder.id is the version-less constant again: %q", id)
	}
	if !strings.HasPrefix(id, builderID+"@") {
		t.Errorf("builder.id = %q, want %s@<version>", id, builderID)
	}
	if got := strings.TrimPrefix(id, builderID+"@"); got != bkVersion() {
		t.Errorf("builder.id names %q, but this bk is %q", got, bkVersion())
	}

	// AND THE QUESTION THE BUILD WAS ASKED, which was an empty object.
	def, _ := pred["buildDefinition"].(map[string]any)
	ext, _ := def["externalParameters"].(map[string]any)
	if len(ext) == 0 {
		t.Fatalf("externalParameters is still empty:\n%v", def)
	}
	for k, want := range map[string]string{
		"project":  "acme.org/tool",
		"version":  "1.2.3",
		"platform": "linux/aarch64",
	} {
		if got, _ := ext[k].(string); got != want {
			t.Errorf("externalParameters[%q] = %q, want %q", k, got, want)
		}
	}
}

// TWO DIFFERENT bk VERSIONS MUST PRODUCE DIFFERENT STATEMENTS. The point is
// not that a version appears, it is that the bytes differ — a reader diffing
// two attestations has to be able to see it.
func TestTwoBuildersProduceDifferentProvenance(t *testing.T) {
	// buildInfo is the seam bkVersion() reads, so two bk versions are two
	// answers from it rather than two binaries.
	old := buildInfo
	t.Cleanup(func() { buildInfo = old })
	at := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: v}}, true
		}
	}

	buildInfo = at("v0.16.0")
	a, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "aarch64",
		[]byte("tarball"), build.SourceRef{}, nil, time.Unix(0, 0).UTC(), nil, provOrigin{})
	if err != nil {
		t.Fatal(err)
	}
	buildInfo = at("v0.17.0")
	b, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "aarch64",
		[]byte("tarball"), build.SourceRef{}, nil, time.Unix(0, 0).UTC(), nil, provOrigin{})
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := provBlob(t, a), provBlob(t, b)
	if string(pa) == string(pb) {
		t.Error("two bk versions produced byte-identical provenance")
	}
	if !strings.Contains(string(pa), "v0.16.0") || !strings.Contains(string(pb), "v0.17.0") {
		t.Errorf("neither statement names its own bk:\n%s\n---\n%s", pa, pb)
	}
}

func provBlob(t *testing.T, refs []artifact.Referrer) []byte {
	t.Helper()
	for _, r := range refs {
		if r.ArtifactType == artifactInToto {
			return r.Blob
		}
	}
	t.Fatal("no in-toto referrer")
	return nil
}

// ⛔⛔ THE AXIS A VULNERABILITY REBUILD MOVES ALONG. When a Go patch release
// fixes a standard-library defect, nothing about the recipe or the upstream
// version changes — only the compiler in the build environment does. An artifact
// that does not record it cannot be asked "were you built with the fixed
// compiler?", and a rebuild counter over such artifacts would be a number
// nobody could derive or check.
//
// DepTokens computed this list on every build and threw it away.
func TestTheProvenanceRecordsTheBuildEnvironment(t *testing.T) {
	env := []moustache.Dep{
		{Project: "go.dev", Version: "1.27.1", Path: "/pkgx/go.dev/v1.27.1"},
		{Project: "gnu.org/glibc", Version: "2.44.0", Path: "/pkgx/gnu.org/glibc/v2.44.0"},
	}
	refs, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "aarch64",
		[]byte("tarball"), build.SourceRef{}, env, time.Unix(0, 0).UTC(), nil, provOrigin{})
	if err != nil {
		t.Fatal(err)
	}
	got := string(provBlob(t, refs))
	for _, want := range []string{"pkg:generic/go.dev@1.27.1", "pkg:generic/gnu.org/glibc@2.44.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("the provenance does not name %s:\n%s", want, got)
		}
	}
	// ⛔ AND THE RETIRED NAMESPACE IS NOT MINTED. `pkgx` is not a registered
	// purl type and is not ours; writing it into a new attestation is the
	// defect go-zpkg/artifact#221 exists for. It is still READ, which
	// TestAArtifactSignedWithTheRetiredPurlIsStillUnderstood covers.
	if strings.Contains(got, "pkg:pkgx/") {
		t.Errorf("a new attestation mints the retired purl namespace:\n%s", got)
	}
	// ⛔ THE PATH IS NOT RECORDED. It is where THIS MACHINE put the artifact,
	// which is not a fact about the artefact — and two builds that differ
	// only by $ZPKG_DIR would otherwise produce different attestations.
	if strings.Contains(got, "/pkgx/go.dev") {
		t.Errorf("the provenance records a local path:\n%s", got)
	}
}

// AND A TOOLCHAIN BUMP CHANGES THE BYTES. The point is not that versions
// appear, it is that the same software built against a different compiler
// produces a different attestation — which is what a rebuild counter would
// have to be derived from.
func TestADifferentToolchainProducesDifferentProvenance(t *testing.T) {
	mk := func(goVer string) string {
		refs, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "aarch64",
			[]byte("tarball"), build.SourceRef{},
			[]moustache.Dep{{Project: "go.dev", Version: goVer}}, time.Unix(0, 0).UTC(), nil, provOrigin{})
		if err != nil {
			t.Fatal(err)
		}
		return string(provBlob(t, refs))
	}
	a, b := mk("1.27.1"), mk("1.27.2")
	if a == b {
		t.Error("the same software built with two different Go versions produced identical provenance")
	}
	if !strings.Contains(a, "go.dev@1.27.1") || !strings.Contains(b, "go.dev@1.27.2") {
		t.Errorf("neither statement names its own toolchain:\n%s\n---\n%s", a, b)
	}
}

// A BUILD WITH NO ENVIRONMENT SAYS NOTHING RATHER THAN SOMETHING EMPTY.
// `bk publish` on an artifact this process did not build, and the mirror path,
// genuinely do not know — and an empty material would assert a dependency on
// nothing.
func TestNoEnvironmentProducesNoMaterials(t *testing.T) {
	refs, err := buildReferrers("acme.org/tool", "1.2.3", "linux", "aarch64",
		[]byte("tarball"), build.SourceRef{}, nil, time.Unix(0, 0).UTC(), nil, provOrigin{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(provBlob(t, refs)), "pkg:pkgx/") {
		t.Errorf("a build that knew no environment claimed one:\n%s", provBlob(t, refs))
	}
}
