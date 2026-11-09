package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tagsRegistry answers the two requests `zbk copy --dry-run` makes: the /v2/
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
// `sha256-<digest>` TAGS, and bottle's own notes record a release reported as
// "2 version(s) tagged" where the two were referrers. Platform tags
// (`<ver>--<os>-<arch>`) are in the same listing.
//
// A copy that took the listing at face value would walk those as versions and
// fail on each — or worse, succeed at copying a referrer as though it were a
// release. bottle.IsVersionTag is what decides, and this asserts the verb asks
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

// The arguments that cannot produce a copy are refused with a usage status,
// before a client is built, so a mistyped invocation costs no request.
func TestCopyArgumentRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
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
