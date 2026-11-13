package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/bottle"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var vexWhen = time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)

const vexAdvisory = `schema-version: 1
project: openssl.org
advisories:
  - id: CVE-2026-0001
    aliases: [GHSA-aaaa-bbbb-cccc]
    events:
      - timestamp: 2026-10-10T12:00:00Z
        type: fixed
        fixed-version: 3.5.8_1
`

// vexTree writes an advisory tree and returns its root.
func vexTree(t *testing.T, project, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, filepath.FromSlash(project), advisoryFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVexReferrerCarriesTheDecision(t *testing.T) {
	dir := vexTree(t, "openssl.org", vexAdvisory)
	ref, err := vexReferrer(dir, "openssl.org", "3.5.8_1", "linux", "x86-64", []byte("bottle"), vexWhen)
	if err != nil {
		t.Fatalf("vexReferrer: %v", err)
	}
	if ref == nil {
		t.Fatal("no referrer for a project that has advisories")
	}
	if ref.ArtifactType != artifactOpenVEX || ref.MediaType != artifactOpenVEX {
		t.Errorf("artifactType = %q", ref.ArtifactType)
	}
	var doc struct {
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Timestamp  string `json:"timestamp"`
		Tooling    string `json:"tooling"`
		Statements []struct {
			Status   string `json:"status"`
			Products []struct {
				ID     string            `json:"@id"`
				Hashes map[string]string `json:"hashes"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(ref.Blob, &doc); err != nil {
		t.Fatalf("the blob is not JSON: %v", err)
	}
	if doc.Statements[0].Status != "fixed" {
		t.Errorf("status = %q", doc.Statements[0].Status)
	}
	// The document is dated with the SAME timestamp the SBOM and provenance
	// use, which is what makes a re-push idempotent.
	if doc.Timestamp != "2026-10-11T09:00:00Z" {
		t.Errorf("timestamp = %q", doc.Timestamp)
	}
	if doc.Author != builderID || doc.Tooling != builderWithVersion() {
		t.Errorf("author = %q, tooling = %q", doc.Author, doc.Tooling)
	}
	// Bound to the tarball digest, the same anchor as the other attestations.
	p := doc.Statements[0].Products[0]
	if p.ID != "pkg:generic/openssl.org@3.5.8_1" {
		t.Errorf("product = %q", p.ID)
	}
	if len(p.Hashes["sha-256"]) != 64 {
		t.Errorf("hashes = %v, want a sha-256 of the tarball", p.Hashes)
	}
}

// ⛔ The document must be byte-identical for the same bottle, or a re-push
// attaches a second referrer beside the first instead of replacing it. The
// @id therefore carries no timestamp and no counter.
func TestVexReferrerIsByteIdenticalOnARePush(t *testing.T) {
	dir := vexTree(t, "openssl.org", vexAdvisory)
	a, err := vexReferrer(dir, "openssl.org", "3.5.8_1", "linux", "x86-64", []byte("bottle"), vexWhen)
	if err != nil {
		t.Fatal(err)
	}
	b, err := vexReferrer(dir, "openssl.org", "3.5.8_1", "linux", "x86-64", []byte("bottle"), vexWhen)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Blob) != string(b.Blob) {
		t.Errorf("two runs differ:\n%s\n---\n%s", a.Blob, b.Blob)
	}
	// And two PLATFORMS are two artefacts, so their documents differ.
	c, err := vexReferrer(dir, "openssl.org", "3.5.8_1", "darwin", "aarch64", []byte("bottle"), vexWhen)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Blob) == string(c.Blob) {
		t.Error("linux and darwin produced the same document")
	}
}

// No tree configured, and no file for this project: no referrer and no error.
// Most projects have never been triaged, and that is not a failure.
func TestVexReferrerIsAbsentWhenNothingWasTriaged(t *testing.T) {
	t.Run("no tree", func(t *testing.T) {
		ref, err := vexReferrer("", "openssl.org", "3.5.8", "linux", "x86-64", []byte("b"), vexWhen)
		if ref != nil || err != nil {
			t.Errorf("ref = %v, err = %v", ref, err)
		}
	})
	t.Run("no file for this project", func(t *testing.T) {
		dir := vexTree(t, "openssl.org", vexAdvisory)
		ref, err := vexReferrer(dir, "curl.se", "8.5.0", "linux", "x86-64", []byte("b"), vexWhen)
		if ref != nil || err != nil {
			t.Errorf("ref = %v, err = %v", ref, err)
		}
	})
}

// ⛔ A file that exists and cannot be used STOPS the publish. The alternative
// is a bottle that looks complete and asserts nothing — and an absent VEX
// document reads as "nothing was ever found", which is the opposite of what a
// broken record means.
func TestVexReferrerRefusesRatherThanOmit(t *testing.T) {
	t.Run("a file that does not parse", func(t *testing.T) {
		dir := vexTree(t, "openssl.org", "schema-version: 1\nproject: openssl.org\nadvisories:\n  - id: CVE-1\n    events:\n      - type: detection\n")
		_, err := vexReferrer(dir, "openssl.org", "3.5.8", "linux", "x86-64", []byte("b"), vexWhen)
		if err == nil || !strings.Contains(err.Error(), "has no timestamp") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a file naming another project", func(t *testing.T) {
		dir := vexTree(t, "openssl.org", strings.Replace(vexAdvisory, "project: openssl.org", "project: curl.se", 1))
		_, err := vexReferrer(dir, "openssl.org", "3.5.8", "linux", "x86-64", []byte("b"), vexWhen)
		if err == nil || !strings.Contains(err.Error(), `says project "curl.se"`) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a file that cannot be read", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read an unreadable file")
		}
		dir := vexTree(t, "openssl.org", vexAdvisory)
		p := filepath.Join(dir, "openssl.org", advisoryFile)
		if err := os.Chmod(p, 0o000); err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
		// NOT the absent case: a permission error must surface, or a bottle
		// whose justification could not be read is published as if it had
		// none.
		_, err := vexReferrer(dir, "openssl.org", "3.5.8", "linux", "x86-64", []byte("b"), vexWhen)
		if err == nil || !strings.Contains(err.Error(), "advisories:") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a document the encoder refuses", func(t *testing.T) {
		// Reached without a seam: OpenVEX requires a timestamp, so an
		// undated call cannot produce a document. publishBottle never passes
		// the zero time — it falls back to buildTime() — but the refusal must
		// reach the caller rather than yielding a document with no date.
		dir := vexTree(t, "openssl.org", vexAdvisory)
		_, err := vexReferrer(dir, "openssl.org", "3.5.8", "linux", "x86-64", []byte("b"), time.Time{})
		if err == nil || !strings.Contains(err.Error(), "no timestamp") {
			t.Errorf("err = %v, want the encoder's refusal", err)
		}
	})
}

// Through publishBottle, which is the only thing the factory calls. The unit
// test above proves the document is right; this proves it is ATTACHED, and
// that the two referrers already there are not displaced.
func TestPublishAttachesTheVexReferrer(t *testing.T) {
	dir := vexTree(t, "openssl.org", vexAdvisory)
	b := writeBottle(t, "b.tar.gz")
	var got []bottle.Referrer
	saved := ociPush
	t.Cleanup(func() { ociPush = saved })
	ociPush = func(_, _, _, _, _ string, _ []byte, _ string, refs []bottle.Referrer, _ map[string]string) (ocispec.Descriptor, error) {
		got = refs
		return ocispec.Descriptor{}, nil
	}
	if _, _, err := publishBottle(publishOptions{
		Dist: "oci://x/y", Project: "openssl.org", Version: "3.5.8_1",
		OS: "linux", Arch: "x86-64", Path: b, Advisories: dir,
	}); err != nil {
		t.Fatalf("publishBottle: %v", err)
	}
	var kinds []string
	for _, r := range got {
		kinds = append(kinds, r.ArtifactType)
	}
	if len(got) != 3 {
		t.Fatalf("referrers = %v, want SBOM + provenance + VEX", kinds)
	}
	if got[2].ArtifactType != artifactOpenVEX {
		t.Errorf("referrers = %v", kinds)
	}
	if !json.Valid(got[2].Blob) || !strings.Contains(string(got[2].Blob), "CVE-2026-0001") {
		t.Errorf("vex blob: %s", got[2].Blob)
	}

	// And with no advisory tree, the other two are unchanged — the VEX
	// referrer is additive, not a replacement.
	got = nil
	if _, _, err := publishBottle(publishOptions{
		Dist: "oci://x/y", Project: "openssl.org", Version: "3.5.8_1",
		OS: "linux", Arch: "x86-64", Path: b,
	}); err != nil {
		t.Fatalf("publishBottle: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("referrers without a tree = %d, want 2", len(got))
	}
}

// A broken advisory file stops publishBottle, so nothing is pushed.
func TestPublishRefusesABrokenAdvisoryFile(t *testing.T) {
	dir := vexTree(t, "openssl.org", "schema-version: 9\n")
	b := writeBottle(t, "b.tar.gz")
	pushed := false
	saved := ociPush
	t.Cleanup(func() { ociPush = saved })
	ociPush = func(string, string, string, string, string, []byte, string, []bottle.Referrer, map[string]string) (ocispec.Descriptor, error) {
		pushed = true
		return ocispec.Descriptor{}, nil
	}
	_, _, err := publishBottle(publishOptions{
		Dist: "oci://x/y", Project: "openssl.org", Version: "3.5.8_1",
		OS: "linux", Arch: "x86-64", Path: b, Advisories: dir,
	})
	if err == nil {
		t.Fatal("published a bottle whose justification could not be read")
	}
	if pushed {
		t.Error("the bottle was pushed anyway")
	}
}

// The document names the platform, because two platforms' bottles are two
// artefacts and a statement about one must not claim to be the other.
func TestVexDocumentIDNamesThePlatform(t *testing.T) {
	a := vexDocumentID("openssl.org", "3.5.8_1", "linux", "x86-64")
	b := vexDocumentID("openssl.org", "3.5.8_1", "darwin", "aarch64")
	if a == b {
		t.Fatal("two platforms share one document id")
	}
	for _, want := range []string{builderID, "openssl.org", "3.5.8_1", "linux-x86-64"} {
		if !strings.Contains(a, want) {
			t.Errorf("%q does not contain %q", a, want)
		}
	}
	// No timestamp, no counter: an id that changed per push would attach a
	// second referrer beside the first.
	if strings.Contains(a, "2026") {
		t.Errorf("the id carries a date: %q", a)
	}
}

// `bk publish --advisories` is a DECLARED flag, not an unknown one.
//
// Both cases exit 2, so the exit code proves nothing; what distinguishes them
// is which complaint comes out. An undeclared flag says "flag provided but not
// defined", a declared one gets as far as the usage line.
func TestPublishDeclaresTheAdvisoriesFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runPublish([]string{"--advisories", "/tmp/x"}, &out, &errb); rc != 2 {
		t.Fatalf("rc = %d", rc)
	}
	if strings.Contains(errb.String(), "not defined") {
		t.Errorf("the flag is not declared: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "usage: bk publish") {
		t.Errorf("want the usage line, got %q", errb.String())
	}
	// And the opposite case, so the test above is known to be able to fail.
	out.Reset()
	errb.Reset()
	if rc := runPublish([]string{"--nonesuch", "x"}, &out, &errb); rc != 2 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(errb.String(), "not defined") {
		t.Errorf("an undeclared flag was accepted: %q", errb.String())
	}
}
