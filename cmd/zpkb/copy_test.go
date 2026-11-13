package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-zpkg/artifact"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// tagsRegistry answers the two requests `zpkb copy --dry-run` makes: the /v2/
// ping and a tag listing. It is deliberately not miniOCI — that one is shared
// with publish_test and pinned to a single namespace, and a copy needs two.
type tagsRegistry struct {
	srv  *httptest.Server
	tags []string
}

func newTagsRegistry(t *testing.T, tags []string) *tagsRegistry {
	t.Helper()
	r := &tagsRegistry{tags: tags}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/v2/" || req.URL.Path == "/v2":
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(req.URL.Path, "/tags/list"):
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "x", "tags": r.tags})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *tagsRegistry) base(ns string) string {
	return "oci://" + strings.TrimPrefix(r.srv.URL, "http://") + "/" + ns
}

// ⛔⛔ A TAG LISTING IS NOT A VERSION LIST, AND THIS FLEET HAS PUBLISHED THAT
// MISTAKE. ghcr implements no referrers API, so ORAS keeps referrers under
// `sha256-<digest>` TAGS, and artifact's own notes record a release reported as
// "2 version(s) tagged" where the two were referrers. Platform tags
// (`<ver>--<os>-<arch>`) are in the same listing.
//
// A copy that took the listing at face value would walk those as versions and
// fail on each — or worse, succeed at copying a referrer as though it were a
// release. artifact.IsVersionTag is what decides, and this asserts the verb asks
// it rather than restating the rule.
func TestCopyDryRunListsOnlyVersionTags(t *testing.T) {
	reg := newTagsRegistry(t, []string{
		"5.3",
		"5.2.37",
		"5.3--linux-x86-64",
		"5.3--darwin-aarch64",
		"sha256-64caff4d6e1b05b8e1f6d0f6d22ba46c7f0b4bb2b3b1e1f5c3a2d1e0f9a8b7c6",
	})
	var out, errb bytes.Buffer
	code := runCopy([]string{
		"--from", reg.base("go-pkgx/packages"),
		"--to", reg.base("go-zpkg/packages"),
		"--project", "gnu.org/bash",
		"--dry-run",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{"5.3", "5.2.37", "2 version(s)"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not mention %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"--linux-x86-64", "--darwin-aarch64", "sha256-"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("a %q tag was listed as a version:\n%s", unwanted, got)
		}
	}
}

// ⛔ "NOTHING TO COPY" MUST NOT EXIT 0. A source that publishes nothing under
// the name asked for, and a source read correctly that happens to be empty,
// print the same empty output — and this fleet has published that zero before,
// from a sweep that could not read its corpus. So an empty version list is a
// failure with a sentence, not a silent success.
func TestCopyRefusesAnEmptyVersionList(t *testing.T) {
	reg := newTagsRegistry(t, []string{
		"sha256-64caff4d6e1b05b8e1f6d0f6d22ba46c7f0b4bb2b3b1e1f5c3a2d1e0f9a8b7c6",
	})
	var out, errb bytes.Buffer
	code := runCopy([]string{
		"--from", reg.base("go-pkgx/packages"),
		"--to", reg.base("go-zpkg/packages"),
		"--project", "gnu.org/bash",
		"--dry-run",
	}, &out, &errb)
	if code == 0 {
		t.Fatalf("a source with no version tag exited 0, output: %q", out.String())
	}
	if !strings.Contains(errb.String(), "publishes no version") {
		t.Errorf("stderr does not say the source publishes nothing: %q", errb.String())
	}
}

// A copy into the namespace it came from is refused before any request. No
// registry is stood up here on purpose: if the refusal needed the network it
// would not be a refusal, it would be an error from one.
func TestCopyRefusesTheSameNamespace(t *testing.T) {
	var out, errb bytes.Buffer
	code := runCopy([]string{
		"--from", "oci://ghcr.io/go-zpkg/packages",
		"--to", "oci://ghcr.io/go-zpkg/packages",
		"--project", "gnu.org/bash",
		"--version", "5.3",
	}, &out, &errb)
	if code == 0 {
		t.Fatal("copied a namespace onto itself")
	}
	if !strings.Contains(errb.String(), "same namespace") {
		t.Errorf("stderr does not name the problem: %q", errb.String())
	}
}

// stubVerifier answers the destination's verification surface.
type stubVerifier struct {
	platforms []string
	platErr   error
	digest    string
	digestErr error
	verifyErr error
}

func (s stubVerifier) Platforms(string, string) ([]string, error) {
	return s.platforms, s.platErr
}
func (s stubVerifier) ArtifactDigest(string, string, string, string) (string, error) {
	return s.digest, s.digestErr
}
func (s stubVerifier) VerifyArtifactDigest(string, string, string, string, string) error {
	return s.verifyErr
}

// ⛔ ZERO PLATFORMS IS THE ONE THAT MATTERS. A version whose index arrived
// without the manifests it names would otherwise report "0 platform(s)
// verified" and exit 0 — the shape of a copy that moved an index and left the
// artifacts behind, reported as a success.
func TestVerifyCopied(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    stubVerifier
		want string // "" means it must succeed
		n    int
	}{
		{"two platforms", stubVerifier{platforms: []string{"linux/x86-64", "darwin/aarch64"}, digest: "sha256:ab"}, "", 2},
		{"the index cannot be read", stubVerifier{platErr: errBoom}, "boom", 0},
		{"the index names no platform", stubVerifier{}, "names no platform", 0},
		{"a platform with no slash", stubVerifier{platforms: []string{"nonsense"}}, "unreadable platform", 0},
		{"the digest cannot be read", stubVerifier{platforms: []string{"linux/x86-64"}, digestErr: errBoom}, "linux/x86-64", 0},
		{"the signature does not verify", stubVerifier{platforms: []string{"linux/x86-64"}, verifyErr: errBoom}, "linux/x86-64", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := verifyCopied(tc.v, "gnu.org/bash", "5.3")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if n != tc.n {
					t.Errorf("verified %d platform(s), want %d", n, tc.n)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// stubCopy replaces the two seams for one test and restores them after.
func stubCopy(t *testing.T, copyErr error, n int, verifyErr error) *int {
	t.Helper()
	oldCopy, oldVerify := copyPublished, verifyAtDestination
	t.Cleanup(func() { copyPublished, verifyAtDestination = oldCopy, oldVerify })
	verified := 0
	copyPublished = func(context.Context, *artifact.OCIClient, *artifact.OCIClient, string, string) (ocispec.Descriptor, error) {
		return ocispec.Descriptor{}, copyErr
	}
	verifyAtDestination = func(copyVerifier, string, string) (int, error) {
		verified++
		return n, verifyErr
	}
	return &verified
}

func TestCopyRunsAndVerifies(t *testing.T) {
	reg := newTagsRegistry(t, []string{"5.3"})
	verified := stubCopy(t, nil, 3, nil)

	var out, errb bytes.Buffer
	code := runCopy([]string{
		"--from", reg.base("go-pkgx/packages"),
		"--to", reg.base("go-zpkg/packages"),
		"--project", "gnu.org/bash",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	if want := "copied gnu.org/bash 5.3, 3 platform(s) verified"; !strings.Contains(out.String(), want) {
		t.Errorf("output does not say %q:\n%s", want, out.String())
	}
	if *verified != 1 {
		t.Errorf("verified %d time(s), want 1", *verified)
	}
}

// --no-verify says what it gives up, and must actually skip the check rather
// than run it quietly: a flag that does nothing is worse than no flag.
func TestCopyNoVerifySkipsTheCheck(t *testing.T) {
	reg := newTagsRegistry(t, []string{"5.3"})
	verified := stubCopy(t, nil, 1, nil)

	var out, errb bytes.Buffer
	code := runCopy([]string{
		"--from", reg.base("go-pkgx/packages"),
		"--to", reg.base("go-zpkg/packages"),
		"--project", "gnu.org/bash",
		"--no-verify",
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "(not verified)") {
		t.Errorf("output does not say the artifact was not verified:\n%s", out.String())
	}
	if *verified != 0 {
		t.Errorf("--no-verify still verified %d time(s)", *verified)
	}
}

func TestCopyReportsAFailedCopy(t *testing.T) {
	reg := newTagsRegistry(t, []string{"5.3"})
	stubCopy(t, errBoom, 0, nil)

	var out, errb bytes.Buffer
	if code := runCopy([]string{
		"--from", reg.base("go-pkgx/packages"),
		"--to", reg.base("go-zpkg/packages"),
		"--project", "gnu.org/bash",
	}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "boom") {
		t.Errorf("stderr does not carry the cause: %q", errb.String())
	}
}

// ⛔ A COPY THAT ARRIVED AND DOES NOT VERIFY IS A FAILURE, and the message has
// to say both things: it was copied, and it cannot be trusted there. Reporting
// only "verification failed" would read as "nothing happened", and something
// did.
func TestCopyReportsAnUnverifiableCopy(t *testing.T) {
	reg := newTagsRegistry(t, []string{"5.3"})
	stubCopy(t, nil, 0, errBoom)

	var out, errb bytes.Buffer
	if code := runCopy([]string{
		"--from", reg.base("go-pkgx/packages"),
		"--to", reg.base("go-zpkg/packages"),
		"--project", "gnu.org/bash",
	}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for _, want := range []string{"copied but does not verify", "gnu.org/bash", "boom"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr does not mention %q: %q", want, errb.String())
		}
	}
}

// A registry that will not list tags is not an empty registry, and the two must
// not print the same thing.
func TestCopyReportsATagListingFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	base := "oci://" + strings.TrimPrefix(srv.URL, "http://") + "/"

	var out, errb bytes.Buffer
	if code := runCopy([]string{
		"--from", base + "go-pkgx/packages",
		"--to", base + "go-zpkg/packages",
		"--project", "gnu.org/bash",
		"--dry-run",
	}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "list the tags") {
		t.Errorf("stderr does not say the listing failed: %q", errb.String())
	}
}

// The dispatch line itself: `zpkb copy` reaches runCopy.
func TestCopyThroughTheDispatcher(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"copy"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2 (usage)", code)
	}
	if !strings.Contains(errb.String(), "are all required") {
		t.Errorf("stderr is not runCopy's usage: %q", errb.String())
	}
}

// The arguments that cannot produce a copy are refused with a usage status,
// before a client is built, so a mistyped invocation costs no request.
func TestCopyArgumentRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		// flag.ContinueOnError prints to the flagset's output, which is stderr
		// here, so an unknown flag names itself rather than ending the process.
		{"a flag that does not exist", []string{"--nope"}, "not defined"},
		{"nothing at all", nil, "are all required"},
		{"no project", []string{"--from", "oci://a/b", "--to", "oci://c/d"}, "are all required"},
		{"no destination", []string{"--from", "oci://a/b", "--project", "p"}, "are all required"},
		{"source is not oci", []string{"--from", "https://a/b", "--to", "oci://c/d", "--project", "p"}, "--from"},
		{"destination is not oci", []string{"--from", "oci://a/b", "--to", "https://c/d", "--project", "p"}, "--to"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := runCopy(tc.args, &out, &errb); code != 2 {
				t.Fatalf("exit %d, want 2 (usage); stderr: %s", code, errb.String())
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr does not mention %q: %q", tc.want, errb.String())
			}
		})
	}
}
