package versions

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

var errBoom = errors.New("boom")

// saveSeams snapshots every injectable seam and restores it after the test.
func saveSeams(t *testing.T) {
	t.Helper()
	hg, glt, hgr, ira := httpGet, gitLsRemoteTags, httpGetRaw, ioReadAll
	glr, hd, og := ghListReleases, httpDo, osGetenv
	t.Cleanup(func() {
		httpGet, gitLsRemoteTags, httpGetRaw, ioReadAll = hg, glt, hgr, ira
		ghListReleases, httpDo, osGetenv = glr, hd, og
	})
}

// TestResolveURLNcurses is the end-to-end proof: an ftp.gnu.org-style listing
// must yield 6.5 (the real upstream file), NOT dist's normalised 6.6.0.
func TestResolveURLNcurses(t *testing.T) {
	saveSeams(t)
	listing := `<a href="ncurses-6.3.tar.gz">ncurses-6.3.tar.gz</a>
<a href="ncurses-6.4.tar.gz">ncurses-6.4.tar.gz</a>
<a href="ncurses-6.5.tar.gz">ncurses-6.5.tar.gz</a>`
	httpGet = func(string) (string, error) { return listing, nil }
	spec := map[string]any{
		"url":   "https://ftp.gnu.org/gnu/ncurses/",
		"match": `/ncurses-\d+(\.\d+)+.tar.gz/`,
		"strip": []any{"/ncurses-/", "/.tar.gz/"},
	}
	v, tag, err := Resolve(spec, "*")
	if err != nil || v != "6.5" {
		t.Fatalf("Resolve = %q, %v; want 6.5", v, err)
	}
	// version.tag is the raw pre-strip matched string (upstream file name).
	if tag != "ncurses-6.5.tar.gz" {
		t.Fatalf("tag = %q; want ncurses-6.5.tar.gz", tag)
	}
}

func TestResolveNpm(t *testing.T) {
	saveSeams(t)
	var gotURL string
	httpGet = func(u string) (string, error) {
		gotURL = u
		return `{"name":"prettier","dist-tags":{"latest":"3.9.6"},"versions":{"3.9.5":{},"3.9.6":{},"2.0.0":{}}}`, nil
	}
	v, _, err := Resolve(map[string]any{"npm": "prettier"}, "*")
	if err != nil || v != "3.9.6" {
		t.Fatalf("npm resolve = %q %v; want 3.9.6", v, err)
	}
	if gotURL != "https://registry.npmjs.org/prettier" {
		t.Errorf("unscoped URL = %q", gotURL)
	}
	// scoped name → slash percent-encoded
	if got := npmRegistryURL("@angular/cli"); got != "https://registry.npmjs.org/@angular%2Fcli" {
		t.Errorf("scoped URL = %q", got)
	}
	// a constrained pick over the registry versions
	if v, _, err := Resolve(map[string]any{"npm": "prettier"}, "^2"); err != nil || v != "2.0.0" {
		t.Errorf("npm ^2 = %q %v", v, err)
	}
	// malformed registry JSON → error
	httpGet = func(string) (string, error) { return "not json", nil }
	if _, _, err := Resolve(map[string]any{"npm": "x"}, "*"); err == nil {
		t.Error("expected npm JSON parse error")
	}
	// httpGet failure propagates
	httpGet = func(string) (string, error) { return "", errBoom }
	if _, _, err := Resolve(map[string]any{"npm": "x"}, "*"); err == nil {
		t.Error("expected npm fetch error")
	}
}

// TestResolveURLCalVer covers the date-style CalVer path (curl.se/ca-certs):
// dash-separated all-numeric versions are rewritten to dotted form so they
// parse and the highest date wins, with zero-padding preserved in version.raw.
func TestResolveURLCalVer(t *testing.T) {
	saveSeams(t)
	listing := `cacert-2025-05-20.pem cacert-2025-08-12.pem cacert-2026-03-19.pem`
	httpGet = func(string) (string, error) { return listing, nil }
	spec := map[string]any{
		"url":   "https://curl.se/docs/caextract.html",
		"match": `/cacert-2\d+-\d+-\d+.pem/`,
		"strip": []any{"/cacert-/", "/\\.pem/"},
	}
	v, tag, err := Resolve(spec, "*")
	if err != nil || v != "2026.03.19" {
		t.Fatalf("Resolve = %q, %v; want 2026.03.19 (padded, dotted)", v, err)
	}
	if tag != "cacert-2026-03-19.pem" {
		t.Fatalf("tag = %q; want cacert-2026-03-19.pem", tag)
	}
	// direct unit check of both branches
	if calverToDotted("2025-08-12") != "2025.08.12" || calverToDotted("1.2.3") != "1.2.3" {
		t.Error("calverToDotted branches")
	}
}

// TestResolveGithub proves github tags select the semver (not lexical) max.
func TestResolveGithub(t *testing.T) {
	saveSeams(t)
	var gotURL string
	gitLsRemoteTags = func(repoURL string) ([]string, error) {
		gotURL = repoURL
		return []string{"v1.2.0", "v1.10.0", "v1.3.0"}, nil
	}
	spec := map[string]any{"github": "owner/repo", "strip": "/v/"}
	v, tag, err := Resolve(spec, "")
	if err != nil || v != "1.10.0" {
		t.Fatalf("Resolve = %q, %v; want 1.10.0", v, err)
	}
	// version.tag = the raw git tag (v-prefixed), not the stripped version.
	if tag != "v1.10.0" {
		t.Fatalf("tag = %q; want v1.10.0", tag)
	}
	if gotURL != "https://github.com/owner/repo" {
		t.Errorf("repoURL = %q", gotURL)
	}
}

func TestResolveGitlab(t *testing.T) {
	saveSeams(t)
	var gotURL string
	gitLsRemoteTags = func(repoURL string) ([]string, error) {
		gotURL = repoURL
		return []string{"v2.1.0", "v2.3.0", "v2.2.0"}, nil
	}
	// default host + decorative /tags suffix
	v, tag, err := Resolve(map[string]any{"gitlab": "group/project/tags", "strip": "/v/"}, "")
	if err != nil || v != "2.3.0" || tag != "v2.3.0" {
		t.Fatalf("gitlab default = %q/%q %v", v, tag, err)
	}
	if gotURL != "https://gitlab.com/group/project" {
		t.Errorf("default-host URL = %q", gotURL)
	}
	// self-hosted "host:" prefix + nested subgroup path
	if _, _, err := Resolve(map[string]any{"gitlab": "gitlab.gnome.org:GNOME/pango/tags"}, "*"); err != nil {
		t.Fatalf("gitlab custom host: %v", err)
	}
	if gotURL != "https://gitlab.gnome.org/GNOME/pango" {
		t.Errorf("custom-host URL = %q", gotURL)
	}
	// invalid spec (no group/project) → error, no ls-remote
	if _, _, err := Resolve(map[string]any{"gitlab": "loneword"}, "*"); err == nil {
		t.Error("expected invalid-gitlab-spec error")
	}
	// a failing ls-remote propagates
	gitLsRemoteTags = func(string) ([]string, error) { return nil, errBoom }
	if _, _, err := Resolve(map[string]any{"gitlab": "group/project"}, "*"); err == nil {
		t.Error("expected gitlab ls-remote error to propagate")
	}
}

// TestResolveGithubNonVTag proves a non-"v" upstream tag (e.g. openssl-3.5.0)
// is preserved verbatim as version.tag while the version strips to 3.5.0.
func TestResolveGithubNonVTag(t *testing.T) {
	saveSeams(t)
	gitLsRemoteTags = func(string) ([]string, error) {
		return []string{"openssl-3.4.0", "openssl-3.5.0"}, nil
	}
	spec := map[string]any{"github": "openssl/openssl", "strip": "/openssl-/"}
	v, tag, err := Resolve(spec, "*")
	if err != nil || v != "3.5.0" {
		t.Fatalf("Resolve = %q, %v; want 3.5.0", v, err)
	}
	if tag != "openssl-3.5.0" {
		t.Fatalf("tag = %q; want openssl-3.5.0", tag)
	}
}

func TestResolveGithubDropsVPrefix(t *testing.T) {
	saveSeams(t)
	// github tags carry a leading "v" and the recipe has no strip → the result
	// is normalised to the pkgx tag form (no v), matching dist artifact tags.
	gitLsRemoteTags = func(string) ([]string, error) {
		return []string{"v5.8.2", "v5.8.3"}, nil
	}
	v, tag, err := Resolve(map[string]any{"github": "tukaani-project/xz"}, "*")
	if err != nil || v != "5.8.3" {
		t.Fatalf("Resolve = %q, %v; want 5.8.3 (v stripped)", v, err)
	}
	// The version drops the v, but version.tag keeps the real git tag.
	if tag != "v5.8.3" {
		t.Fatalf("tag = %q; want v5.8.3", tag)
	}
}

// TestResolveGithubSuffixForms accepts every "list tags" spelling: the bare
// owner/repo form and a decorative /tags suffix both list git tags.
func TestResolveGithubSuffixForms(t *testing.T) {
	saveSeams(t)
	gitLsRemoteTags = func(string) ([]string, error) {
		return []string{"refs/tags/1.0.0", "refs/tags/1.1.0"}, nil
	}
	// The releases forms MUST NOT reach the git-tag seam.
	ghListReleases = func(string) ([]ghRelease, error) {
		t.Fatalf("tags form must not call ghListReleases")
		return nil, nil
	}
	for _, gh := range []string{"o/r", "o/r/tags"} {
		v, tag, err := Resolve(map[string]any{"github": gh}, "*")
		if err != nil || v != "1.1.0" {
			t.Errorf("%s: Resolve = %q, %v; want 1.1.0", gh, v, err)
		}
		if tag != "1.1.0" {
			t.Errorf("%s: tag = %q; want 1.1.0", gh, tag)
		}
	}
}

// TestGithubMode pins the tags-vs-releases-vs-releases/tags routing rule.
func TestGithubMode(t *testing.T) {
	cases := map[string]githubListMode{
		"o/r":               ghTags,
		"o/r/tags":          ghTags,
		"o/r/releases":      ghReleaseNames,
		"o/r/releases/tags": ghReleaseTags,
		// a repo literally named "releases" still lists tags (suffix-only scan).
		"o/releases": ghTags,
	}
	for gh, want := range cases {
		if got := githubMode(gh); got != want {
			t.Errorf("githubMode(%q) = %d; want %d", gh, got, want)
		}
	}
}

// TestResolveGithubReleases proves the curl-style case: git tags are messy but
// Release NAMES are clean semver, so `github: owner/repo/releases` resolves via
// release names. The strip `/^curl /` only affects the legacy "curl 7.88.0"
// name; an empty-name release falls back to its tag_name.
func TestResolveGithubReleases(t *testing.T) {
	saveSeams(t)
	var gotURL string
	// If git tags were (wrongly) consulted they'd be unparseable and fail.
	gitLsRemoteTags = func(string) ([]string, error) {
		return []string{"curl-8_21_0", "tiny-curl-8_4_0", "rc-8_22_0-1"}, nil
	}
	ghListReleases = func(apiURL string) ([]ghRelease, error) {
		gotURL = apiURL
		return []ghRelease{
			{Name: "8.21.0", TagName: "curl-8_21_0"},
			{Name: "8.20", TagName: "curl-8_20_0"},
			{Name: "curl 7.88.0", TagName: "curl-7_88_0"},
			{Name: "", TagName: "v6.0.0"}, // empty name → falls back to tag_name
		}, nil
	}
	spec := map[string]any{"github": "curl/curl/releases", "strip": "/^curl /"}
	// Latest wins: 8.21.0 — and its TAG is the git tag the release points at,
	// not its display name. This assertion used to read `tag != "8.21.0"`,
	// which is precisely the defect: a recipe interpolating {{version.tag}}
	// into a download URL got the human name and fetched a 404. The whole
	// reason to prefer this listing is that release NAMES parse as semver
	// where the tags do not; that makes the two different by construction.
	v, tag, err := Resolve(spec, "*")
	if err != nil || v != "8.21.0" || tag != "curl-8_21_0" {
		t.Fatalf("Resolve = %q/%q %v; want 8.21.0/curl-8_21_0", v, tag, err)
	}
	if gotURL != "https://api.github.com/repos/curl/curl/releases?per_page=100" {
		t.Errorf("releases URL = %q", gotURL)
	}
	// The full candidate set resolves as expected, incl. the space-stripped
	// legacy name and the empty-name→tag_name fallback (v-prefix dropped).
	got, err := List(spec)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var vs []string
	for _, e := range got {
		vs = append(vs, e.Version)
	}
	want := []string{"8.21.0", "8.20", "7.88.0", "6.0.0"}
	if !reflect.DeepEqual(vs, want) {
		t.Fatalf("List versions = %v; want %v", vs, want)
	}
	// A constraint picks the newest satisfying it, not the overall max.
	if v, _, err := Resolve(spec, "^7"); err != nil || v != "7.88.0" {
		t.Errorf("constrained = %q %v; want 7.88.0", v, err)
	}
}

// TestResolveGithubReleaseTags proves the /releases/tags form lists each
// release's tag_name (not its display name).
func TestResolveGithubReleaseTags(t *testing.T) {
	saveSeams(t)
	ghListReleases = func(string) ([]ghRelease, error) {
		return []ghRelease{
			{Name: "8.21.0", TagName: "v8.21.0"},
			{Name: "8.20.0", TagName: "v8.20.0"},
		}, nil
	}
	// Uses tag_name "v8.21.0" → v dropped → 8.21.0, tag stays v8.21.0.
	v, tag, err := Resolve(map[string]any{"github": "o/r/releases/tags"}, "*")
	if err != nil || v != "8.21.0" || tag != "v8.21.0" {
		t.Fatalf("Resolve = %q/%q %v; want 8.21.0/v8.21.0", v, tag, err)
	}
}

// TestResolveGithubReleasesErrors covers the releases-path error branches:
// an invalid owner/repo and a failing releases listing.
func TestResolveGithubReleasesErrors(t *testing.T) {
	saveSeams(t)
	// owner/repo validation failure on the releases path.
	if _, _, err := Resolve(map[string]any{"github": "owner//releases"}, "*"); err == nil {
		t.Error("invalid owner/repo on releases path: want error")
	}
	// a failing releases listing propagates.
	ghListReleases = func(string) ([]ghRelease, error) { return nil, errBoom }
	if _, _, err := Resolve(map[string]any{"github": "o/r/releases"}, "*"); err == nil {
		t.Error("releases listing error: want propagation")
	}
}

func TestResolveConstraintAndIgnore(t *testing.T) {
	saveSeams(t)
	gitLsRemoteTags = func(string) ([]string, error) {
		return []string{"1.2.0", "1.5.0", "2.0.0"}, nil
	}
	// constraint filters out 2.0.0, so max satisfying ^1 is 1.5.0.
	if v, tag, err := Resolve(map[string]any{"github": "o/r"}, "^1"); err != nil || v != "1.5.0" || tag != "1.5.0" {
		t.Errorf("constraint: %q %q %v", v, tag, err)
	}
	// ignore drops the 1.x line, leaving 2.0.0.
	spec := map[string]any{"github": "o/r", "ignore": `/^1\./`}
	if v, tag, err := Resolve(spec, "*"); err != nil || v != "2.0.0" || tag != "2.0.0" {
		t.Errorf("ignore: %q %q %v", v, tag, err)
	}
}

func TestResolveListForm(t *testing.T) {
	saveSeams(t)
	// A single-entry hardcoded list: the entry is both the version and the
	// tag, and its raw scalar text ("3.0") must survive verbatim — NOT be
	// re-rendered as "3" (which would 404 the distributable URL).
	if v, tag, err := Resolve([]any{"3.0"}, "*"); err != nil || v != "3.0" || tag != "3.0" {
		t.Errorf("single-entry list = %q %q %v; want 3.0/3.0", v, tag, err)
	}
	// Multi-entry list with no constraint selects the max.
	if v, tag, err := Resolve([]any{"3.0", "3.1", "7", "7.0.6"}, ""); err != nil || v != "7.0.6" || tag != "7.0.6" {
		t.Errorf("multi-entry max = %q %q %v; want 7.0.6", v, tag, err)
	}
	// A constraint picks the max satisfying it, not the overall max.
	if v, _, err := Resolve([]any{"3.0", "3.1", "7", "7.0.6"}, "^3"); err != nil || v != "3.1" {
		t.Errorf("constrained list = %q %v; want 3.1", v, err)
	}
	// An int/string/float mix (as pantry hands it over: verbatim scalar text)
	// preserves each entry's exact text.
	if v, tag, err := Resolve([]any{"7", "3.0"}, "^3"); err != nil || v != "3.0" || tag != "3.0" {
		t.Errorf("mixed-text list = %q %q %v; want 3.0/3.0", v, tag, err)
	}
	// An empty list has no candidates.
	if _, _, err := Resolve([]any{}, "*"); err == nil {
		t.Error("empty list: expected no-candidate error")
	}
}

func TestResolveUnparseableCandidatesSkipped(t *testing.T) {
	saveSeams(t)
	httpGet = func(string) (string, error) { return "foo 1.2.3 bar", nil }
	// match grabs words; "foo"/"bar" are unparseable and skipped, 1.2.3 wins.
	spec := map[string]any{"url": "u", "match": `/[a-z0-9.]+/`}
	if v, tag, err := Resolve(spec, "*"); err != nil || v != "1.2.3" || tag != "1.2.3" {
		t.Errorf("Resolve = %q %q %v; want 1.2.3", v, tag, err)
	}
}

// TestResolveLookaheadMatch proves that a recipe `match:` using a lookahead —
// which Go's stdlib regexp (RE2) rejects outright — compiles and matches via our
// go-regexp/engine. This is gopls's real spec form: a version followed by a
// closing quote or angle bracket in an HTML/JSON listing, excluding versions
// that are not so followed.
func TestResolveLookaheadMatch(t *testing.T) {
	saveSeams(t)
	httpGet = func(string) (string, error) {
		return `href="v1.2.3" and v9.9.9 bare and <v4.5.6"`, nil
	}
	// v9.9.9 is followed by a space, so the (?=["<]) lookahead excludes it;
	// v1.2.3 and v4.5.6 are each followed by a quote and win.
	spec := map[string]any{"url": "u", "match": `/v\d+\.\d+\.\d+(?=["<])/`}
	got, err := List(spec)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var vs []string
	for _, vt := range got {
		vs = append(vs, vt.Version)
	}
	// List returns newest-first; both survivors, 9.9.9 excluded by lookahead.
	want := []string{"4.5.6", "1.2.3"}
	if !reflect.DeepEqual(vs, want) {
		t.Fatalf("lookahead List = %v; want %v", vs, want)
	}
}

func TestResolveErrors(t *testing.T) {
	saveSeams(t)
	cases := map[string]struct {
		spec       any
		constraint string
		setup      func()
	}{
		"not-a-map":      {spec: "hello"},
		"bad-strip":      {spec: map[string]any{"github": "o/r", "strip": "/[/"}},
		"bad-ignore":     {spec: map[string]any{"github": "o/r", "ignore": "/[/"}},
		"bad-github":     {spec: map[string]any{"github": "owner"}},
		"empty-github":   {spec: map[string]any{"github": ""}},
		"git-error":      {spec: map[string]any{"github": "o/r"}, setup: func() { gitLsRemoteTags = func(string) ([]string, error) { return nil, errBoom } }},
		"url-no-match":   {spec: map[string]any{"url": "u"}},
		"match-no-url":   {spec: map[string]any{"match": "/x/"}},
		"bad-match":      {spec: map[string]any{"url": "u", "match": "/[/"}},
		"http-error":     {spec: map[string]any{"url": "u", "match": "/x/"}, setup: func() { httpGet = func(string) (string, error) { return "", errBoom } }},
		"neither":        {spec: map[string]any{"summary": "x"}},
		"no-candidate":   {spec: map[string]any{"url": "u", "match": `/\d+\.\d+/`}, setup: func() { httpGet = func(string) (string, error) { return "no versions here", nil } }},
		"bad-constraint": {spec: map[string]any{"github": "o/r"}, constraint: "@@@bad", setup: func() { gitLsRemoteTags = func(string) ([]string, error) { return []string{"1.0.0"}, nil } }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			saveSeams(t)
			if tc.setup != nil {
				tc.setup()
			}
			if _, _, err := Resolve(tc.spec, tc.constraint); err == nil {
				t.Errorf("%s: expected error", name)
			}
		})
	}
}

// TestListGithub proves List returns EVERY parseable github tag, deduped by
// resolved version and sorted descending, each carrying its raw pre-strip tag.
func TestListGithub(t *testing.T) {
	saveSeams(t)
	gitLsRemoteTags = func(string) ([]string, error) {
		// intentionally out of order, with a v-dup and an unparseable entry.
		return []string{"v1.2.0", "v1.10.0", "1.10.0", "v1.3.0", "nightly"}, nil
	}
	got, err := List(map[string]any{"github": "owner/repo", "strip": ""})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// "nightly" dropped (unparseable); v1.10.0 & 1.10.0 dedup to one 1.10.0.
	want := []VersionTag{
		{Version: "1.10.0", Tag: "v1.10.0"},
		{Version: "1.3.0", Tag: "v1.3.0"},
		{Version: "1.2.0", Tag: "v1.2.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("List = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List[%d] = %v; want %v", i, got[i], want[i])
		}
	}
}

// TestListStripAndIgnore covers the strip + ignore + tag-preservation branches:
// the version is post-strip but the Tag stays the raw upstream candidate.
func TestListStripAndIgnore(t *testing.T) {
	saveSeams(t)
	gitLsRemoteTags = func(string) ([]string, error) {
		return []string{"openssl-3.4.0", "openssl-3.5.0", "openssl-1.0.0"}, nil
	}
	spec := map[string]any{"github": "openssl/openssl", "strip": "/openssl-/", "ignore": `/^1\./`}
	got, err := List(spec)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []VersionTag{
		{Version: "3.5.0", Tag: "openssl-3.5.0"},
		{Version: "3.4.0", Tag: "openssl-3.4.0"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("List = %v; want %v (1.0.0 ignored)", got, want)
	}
}

// TestListForm covers the []any (hardcoded list) spec: every entry is a
// candidate, verbatim text preserved, sorted descending with no strip/ignore.
func TestListForm(t *testing.T) {
	saveSeams(t)
	got, err := List([]any{"3.0", "3.1", "7", "7.0.6"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []VersionTag{
		{Version: "7.0.6", Tag: "7.0.6"},
		{Version: "7", Tag: "7"},
		{Version: "3.1", Tag: "3.1"},
		{Version: "3.0", Tag: "3.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("List = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List[%d] = %v; want %v", i, got[i], want[i])
		}
	}
}

// TestListNpmAndURL covers the remaining candidate sources through List.
func TestListNpmAndURL(t *testing.T) {
	saveSeams(t)
	httpGet = func(string) (string, error) {
		return `{"versions":{"1.0.0":{},"2.0.0":{},"1.5.0":{}}}`, nil
	}
	npm, err := List(map[string]any{"npm": "prettier"})
	if err != nil || len(npm) != 3 || npm[0].Version != "2.0.0" || npm[2].Version != "1.0.0" {
		t.Fatalf("npm List = %v %v", npm, err)
	}
	httpGet = func(string) (string, error) {
		return `<a href="ncurses-6.3.tar.gz"><a href="ncurses-6.5.tar.gz">`, nil
	}
	url, err := List(map[string]any{
		"url":   "https://ftp.gnu.org/gnu/ncurses/",
		"match": `/ncurses-\d+(\.\d+)+.tar.gz/`,
		"strip": []any{"/ncurses-/", "/.tar.gz/"},
	})
	if err != nil || len(url) != 2 || url[0].Version != "6.5" || url[0].Tag != "ncurses-6.5.tar.gz" {
		t.Fatalf("url List = %v %v", url, err)
	}
}

func TestListErrors(t *testing.T) {
	saveSeams(t)
	// unsupported spec type
	if _, err := List("hello"); err == nil {
		t.Error("string spec: want error")
	}
	// gatherCandidates error propagates (bad github spec)
	if _, err := List(map[string]any{"github": "owner"}); err == nil {
		t.Error("bad github: want error")
	}
	// no parseable candidate
	gitLsRemoteTags = func(string) ([]string, error) { return []string{"nightly", "edge"}, nil }
	if _, err := List(map[string]any{"github": "o/r"}); err == nil {
		t.Error("no candidate: want error")
	}
}

func TestRegexList(t *testing.T) {
	if l, err := regexList(nil); err != nil || l != nil {
		t.Errorf("nil: %v %v", l, err)
	}
	if l, err := regexList("/x/"); err != nil || len(l) != 1 {
		t.Errorf("string: %v %v", l, err)
	}
	if l, err := regexList([]any{"/a/", "/b/"}); err != nil || len(l) != 2 {
		t.Errorf("list: %v %v", l, err)
	}
	if _, err := regexList([]any{5}); err == nil {
		t.Error("non-string list entry: want error")
	}
	if _, err := regexList([]any{"/[/"}); err == nil {
		t.Error("bad regex in list: want error")
	}
	if _, err := regexList(42); err == nil {
		t.Error("invalid type: want error")
	}
}

func TestCompileDelim(t *testing.T) {
	if re, err := compileDelim("/ab/"); err != nil || re.String() != "ab" {
		t.Errorf("delimited: %v %v", re, err)
	}
	if re, err := compileDelim("ab"); err != nil || re.String() != "ab" {
		t.Errorf("bare: %v %v", re, err)
	}
	if _, err := compileDelim("/[/"); err == nil {
		t.Error("bad regex: want error")
	}
}

func TestGithubRepoURL(t *testing.T) {
	if u, err := githubRepoURL("o/r/tags"); err != nil || u != "https://github.com/o/r" {
		t.Errorf("valid: %q %v", u, err)
	}
	if _, err := githubRepoURL("solo"); err == nil {
		t.Error("no repo: want error")
	}
	if _, err := githubRepoURL("/r"); err == nil {
		t.Error("empty owner: want error")
	}
}

func TestHTTPGetSeam(t *testing.T) {
	saveSeams(t)
	// success
	httpGetRaw = func(string) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("hello"))}, nil
	}
	if body, err := httpGet("u"); err != nil || body != "hello" {
		t.Errorf("success: %q %v", body, err)
	}
	// GET error
	httpGetRaw = func(string) (*http.Response, error) { return nil, errBoom }
	if _, err := httpGet("u"); err == nil {
		t.Error("GET error: want error")
	}
	// non-200
	httpGetRaw = func(string) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	if _, err := httpGet("u"); err == nil {
		t.Error("404: want error")
	}
	// read error
	httpGetRaw = func(string) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("x"))}, nil
	}
	ioReadAll = func(io.Reader) ([]byte, error) { return nil, errBoom }
	if _, err := httpGet("u"); err == nil {
		t.Error("read error: want error")
	}
}

// gitAdvertisement builds a git smart-HTTP upload-pack ref advertisement
// (the GET /info/refs?service=git-upload-pack body) from ordered name→sha refs;
// the first ref carries the \x00-delimited capabilities, per the protocol.
func gitAdvertisement(refs [][2]string) string {
	pkt := func(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
	var b strings.Builder
	b.WriteString(pkt("# service=git-upload-pack\n") + "0000")
	for i, r := range refs {
		line := r[1] + " " + r[0]
		if i == 0 {
			line += "\x00symref=HEAD:refs/heads/main agent=test"
		}
		b.WriteString(pkt(line + "\n"))
	}
	b.WriteString("0000")
	return b.String()
}

func TestGitLsRemoteTagsSeam(t *testing.T) {
	saveSeams(t)
	// Pure-Go go-git ls-remote against a smart-HTTP server advertising tags.
	adv := gitAdvertisement([][2]string{
		{"HEAD", "1111111111111111111111111111111111111111"},
		{"refs/heads/main", "1111111111111111111111111111111111111111"},
		{"refs/tags/v1.0.0", "2222222222222222222222222222222222222222"},
		{"refs/tags/v2.0.0", "3333333333333333333333333333333333333333"},
		{"refs/tags/v2.0.0^{}", "4444444444444444444444444444444444444444"}, // peeled → dropped
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, adv)
	}))
	defer srv.Close()
	tags, err := gitLsRemoteTags(srv.URL)
	if err != nil {
		t.Fatalf("ls-remote: %v", err)
	}
	got := map[string]bool{}
	for _, tg := range tags {
		got[tg] = true
	}
	if len(tags) != 2 || !got["v1.0.0"] || !got["v2.0.0"] {
		t.Fatalf("tags = %v (want v1.0.0,v2.0.0; HEAD/branch excluded, ^{} dropped)", tags)
	}
	// a server that does not speak the protocol → error
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer bad.Close()
	if _, err := gitLsRemoteTags(bad.URL); err == nil {
		t.Error("bad server: want error")
	}
}

// TestGhListReleasesSeam covers the default ghListReleases body: header/auth
// wiring against a real httptest server plus every error branch. It mirrors
// TestGitLsRemoteTagsSeam (real server for the happy path) and TestHTTPGetSeam
// (seam overrides for the transport/read errors).
func TestGhListReleasesSeam(t *testing.T) {
	saveSeams(t)

	// success WITH a token: the Authorization + Accept headers are set and the
	// JSON array of {name,tag_name} is parsed.
	var gotAuth, gotAccept, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAccept, gotUA = r.Header.Get("Authorization"), r.Header.Get("Accept"), r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, `[{"name":"8.21.0","tag_name":"curl-8_21_0"},{"name":"","tag_name":"v8.20.0"}]`)
	}))
	defer srv.Close()
	osGetenv = func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "sekret"
		}
		return ""
	}
	rels, err := ghListReleases(srv.URL)
	if err != nil || len(rels) != 2 || rels[0].Name != "8.21.0" || rels[1].TagName != "v8.20.0" {
		t.Fatalf("releases = %v %v", rels, err)
	}
	if gotAuth != "Bearer sekret" {
		t.Errorf("Authorization = %q; want Bearer sekret", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	// GitHub's REST API requires a User-Agent (403s requests without one).
	if gotUA != userAgent {
		t.Errorf("User-Agent = %q; want %q", gotUA, userAgent)
	}

	// success WITHOUT a token: no Authorization header is sent.
	osGetenv = func(string) string { return "" }
	if _, err := ghListReleases(srv.URL); err != nil {
		t.Fatalf("no-token releases: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization sent without token: %q", gotAuth)
	}

	// NewRequest error: an unparseable URL.
	if _, err := ghListReleases("://bad"); err == nil {
		t.Error("bad URL: want NewRequest error")
	}

	// transport (httpDo) error propagates.
	httpDo = func(*http.Request) (*http.Response, error) { return nil, errBoom }
	if _, err := ghListReleases("https://api.github.com/x"); err == nil {
		t.Error("httpDo error: want error")
	}

	// non-200 status → error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer bad.Close()
	httpDo = http.DefaultClient.Do
	if _, err := ghListReleases(bad.URL); err == nil {
		t.Error("403: want error")
	}

	// read error via the ioReadAll seam (200 body, failing read).
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[]`)
	}))
	defer ok.Close()
	ioReadAll = func(io.Reader) ([]byte, error) { return nil, errBoom }
	if _, err := ghListReleases(ok.URL); err == nil {
		t.Error("read error: want error")
	}
	ioReadAll = io.ReadAll

	// malformed JSON → parse error.
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `not json`)
	}))
	defer junk.Close()
	if _, err := ghListReleases(junk.URL); err == nil {
		t.Error("bad JSON: want parse error")
	}
}

// TestHTTPGetRawSeam covers the default httpGetRaw body: it must send bk's
// User-Agent (Go's default "Go-http-client/2.0" is 403'd by some url-listing
// hosts such as sourceforge) and surface a NewRequest error on a bad URL.
func TestHTTPGetRawSeam(t *testing.T) {
	saveSeams(t)

	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, "listing")
	}))
	defer srv.Close()

	resp, err := httpGetRaw(srv.URL)
	if err != nil {
		t.Fatalf("httpGetRaw: %v", err)
	}
	resp.Body.Close()
	if gotUA != userAgent {
		t.Errorf("User-Agent = %q; want %q", gotUA, userAgent)
	}

	// NewRequest error: an unparseable URL.
	if _, err := httpGetRaw("://bad"); err == nil {
		t.Error("bad URL: want NewRequest error")
	}
}

// TestListAndResolveSourceBlocks: a list-form `versions:` can hold source
// blocks rather than literal versions. Stringifying a block yielded
// "map[match:… url:…]", which matches nothing — every such recipe failed with
// "no candidate version matched" however healthy its sources were.
func TestListAndResolveSourceBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="linux-6.1.2.tar.xz">linux-6.1.2.tar.xz</a> <a href="linux-6.2.0.tar.xz">x</a>`)
	}))
	defer srv.Close()
	spec := []any{
		map[string]any{
			"url":   srv.URL + "/",
			"match": `/linux-\d+\.\d+\.\d+\.tar\.xz/`,
			"strip": []any{"/linux-/", `/\.tar\.xz/`},
		},
	}
	got, err := List(spec)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].Version != "6.2.0" {
		t.Errorf("List = %v, want the two versions newest-first", got)
	}
	v, _, err := Resolve(spec, "*")
	if err != nil || v != "6.2.0" {
		t.Errorf("Resolve = %q err=%v, want 6.2.0", v, err)
	}
	// a list of literal versions keeps working
	if v, _, err := Resolve([]any{"1.2.3", "1.3.0"}, "*"); err != nil || v != "1.3.0" {
		t.Errorf("literal list: %q err=%v", v, err)
	}
	// a malformed block is reported by BOTH entry points, not silently skipped
	if _, err := List([]any{map[string]any{"strip": 42}}); err == nil {
		t.Error("List: expected an error for a malformed source block")
	}
	if _, _, err := Resolve([]any{map[string]any{"strip": 42}}, "*"); err == nil {
		t.Error("Resolve: expected an error for a malformed source block")
	}
}

// TestReleaseNameIsNotTheTag is the case that sent a real recipe to a 404:
// alembic resolves versions from `github: sqlalchemy/alembic/releases`, whose
// release NAME is "1.19.2" while the git tag is "rel_1_19_2", and interpolates
// {{version.tag}} into an archive URL. Seven recipes in the pantry have that
// exact combination.
func TestReleaseNameIsNotTheTag(t *testing.T) {
	saveSeams(t)
	ghListReleases = func(string) ([]ghRelease, error) {
		return []ghRelease{
			{Name: "1.19.2", TagName: "rel_1_19_2"},
			{Name: "1.19.1", TagName: "rel_1_19_1"},
		}, nil
	}
	spec0 := map[string]any{"github": "sqlalchemy/alembic/releases"}
	v, tag, err := Resolve(spec0, "*")
	if err != nil || v != "1.19.2" || tag != "rel_1_19_2" {
		t.Fatalf("Resolve = %q/%q %v; want 1.19.2/rel_1_19_2", v, tag, err)
	}
	// `bk versions` reads the SAME field a recipe interpolates. Reporting the
	// display name here while a build uses the git tag would make the command a
	// person reaches for to debug a 404 quietly agree with the 404.
	lst, err := List(spec0)
	if err != nil || len(lst) != 2 || lst[0].Tag != "rel_1_19_2" || lst[1].Tag != "rel_1_19_1" {
		t.Fatalf("List = %+v %v; want the git tags", lst, err)
	}

	// A release whose name IS its tag contributes no mapping — the map exists
	// only for the difference, so the common case stays exactly as before.
	ghListReleases = func(string) ([]ghRelease, error) {
		return []ghRelease{{Name: "v2.0.0", TagName: "v2.0.0"}}, nil
	}
	if v, tag, err := Resolve(map[string]any{"github": "o/r/releases"}, "*"); err != nil || v != "2.0.0" || tag != "v2.0.0" {
		t.Fatalf("Resolve = %q/%q %v; want 2.0.0/v2.0.0", v, tag, err)
	}

	// …and the /releases/tags form, which lists tag_names as the candidates
	// themselves, is untouched: the candidate already IS the tag.
	ghListReleases = func(string) ([]ghRelease, error) {
		return []ghRelease{{Name: "ICU 76.1", TagName: "v76.1.0"}}, nil
	}
	if v, tag, err := Resolve(map[string]any{"github": "o/r/releases/tags"}, "*"); err != nil || v != "76.1.0" || tag != "v76.1.0" {
		t.Fatalf("releases/tags: %q/%q %v; want 76.1.0/v76.1.0", v, tag, err)
	}

	// A multi-source spec mixing a releases block with a tags block keeps each
	// candidate's own tag: mergeTags folds the maps rather than replacing them.
	gitLsRemoteTags = func(string) ([]string, error) { return []string{"refs/tags/v0.9.0"}, nil }
	ghListReleases = func(string) ([]ghRelease, error) {
		return []ghRelease{{Name: "1.19.2", TagName: "rel_1_19_2"}}, nil
	}
	spec := []any{
		map[string]any{"github": "sqlalchemy/alembic/releases"},
		map[string]any{"github": "o/r"},
	}
	if v, tag, err := Resolve(spec, "*"); err != nil || v != "1.19.2" || tag != "rel_1_19_2" {
		t.Fatalf("mixed: %q/%q %v; want 1.19.2/rel_1_19_2", v, tag, err)
	}
	if v, tag, err := Resolve(spec, "<1"); err != nil || v != "0.9.0" || tag != "v0.9.0" {
		t.Fatalf("mixed, tags block wins: %q/%q %v; want 0.9.0/v0.9.0", v, tag, err)
	}
}
