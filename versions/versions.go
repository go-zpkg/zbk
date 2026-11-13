// Package versions resolves a project's upstream version from a pantry
// recipe's `versions:` specification.
//
// This is deliberately distinct from bottle.PickVersion (which lists pkgx's
// already-built bottles at dist.pkgx.dev): dist may advertise a normalised
// version — e.g. ncurses 6.6.0 — that does not exist at the recipe's
// distributable URL (upstream only ships ncurses-6.5.tar.gz). For a fresh
// build the version MUST come from the recipe's own `versions:` field so it
// matches the distributable URL, which interpolates {{version.raw}}.
//
// The logic mirrors libpkgx's usePantry version handling: list a GitHub repo's
// git tags or its REST Release names, or GET an upstream listing and
// regex-match version strings, then strip/ignore/select via the loose
// pkgx-compatible semver.
package versions

import (
	"github.com/go-zpkg/zpkb/useragent"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/storage/memory"
	// onigmo is our pure-Go Onigmo regex engine: recipe strip/ignore/match
	// patterns may use lookahead/lookbehind/backrefs that Go's stdlib regexp
	// (RE2) rejects (e.g. gopls's match `/v\d+\.\d+\.\d+(?=["<])/`).
	onigmo "github.com/go-regexp/engine"
	"github.com/go-versions/semver"
)

// Injectable seams over the two external effects (network + git). Production
// uses the real implementations verbatim; tests swap them to feed fixture
// listings / tag lists and to exercise every error branch without a network.
var (
	// httpGet performs a GET and returns the response body as a string.
	httpGet = func(url string) (string, error) {
		resp, err := httpGetRaw(url)
		if err != nil {
			return "", fmt.Errorf("versions: GET %s: %w", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("versions: GET %s: %s", url, resp.Status)
		}
		body, err := ioReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("versions: read %s: %w", url, err)
		}
		return string(body), nil
	}

	// gitLsRemoteTags lists a repo's tag names with go-git's pure-Go remote
	// listing — NOT a shell-out to the `git` binary (keeps bk portable /
	// dependency-free) and NOT the GitHub API (which rate-limits unauthenticated
	// CI at 60 req/h). go-git speaks the smart-HTTP ref advertisement in-process
	// and works for any Git host (GitHub and GitLab alike). Short() strips the
	// leading refs/tags/; peeled "^{}" entries are skipped.
	gitLsRemoteTags = func(repoURL string) ([]string, error) {
		rem := gogit.NewRemote(memory.NewStorage(), &gitconfig.RemoteConfig{Name: "origin", URLs: []string{repoURL}})
		refs, err := rem.List(&gogit.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("versions: ls-remote %s: %w", repoURL, describeRemoteErr(err))
		}
		var tags []string
		for _, ref := range refs {
			if ref.Name().IsTag() && !strings.HasSuffix(ref.Name().String(), "^{}") {
				tags = append(tags, ref.Name().Short())
			}
		}
		return tags, nil
	}

	// ghListReleases lists a GitHub repo's Release entries (their human `name`
	// and underlying `tag_name`) via the REST Releases API. It exists because a
	// repo's git TAGS are often not semver-parseable while its RELEASE names are:
	// curl tags releases `curl-8_21_0` (space/underscore mess after a strip) but
	// names the release `8.21.0`. Recipes select this source with the
	// `github: owner/repo/releases` form; gatherCandidates routes here then.
	//
	// The GitHub REST API rate-limits UNAUTHENTICATED requests to 60/h — the very
	// reason gitLsRemoteTags speaks go-git instead — so when GITHUB_TOKEN is set
	// the request carries `Authorization: Bearer <token>` (plus the recommended
	// `Accept: application/vnd.github+json`). Only page 1 is fetched
	// (per_page=100 = the 100 newest releases, newest-first), which is ample for
	// latest-version resolution.
	ghListReleases = func(apiURL string) ([]ghRelease, error) {
		req, err := http.NewRequest(http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("versions: releases %s: %w", apiURL, err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/vnd.github+json")
		if tok := osGetenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := httpDoRetrying(req)
		if err != nil {
			return nil, fmt.Errorf("versions: releases %s: %w", apiURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("versions: releases %s: %s", apiURL, resp.Status)
		}
		body, err := ioReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("versions: read %s: %w", apiURL, err)
		}
		var rels []ghRelease
		if err := json.Unmarshal(body, &rels); err != nil {
			return nil, fmt.Errorf("versions: releases %s: %w", apiURL, err)
		}
		return rels, nil
	}

	// httpGetRaw performs the low-level GET behind httpGet's url-listing path,
	// sending bk's own User-Agent: Go's default "Go-http-client/2.0" is rejected
	// by some listing hosts (sourceforge 403s it), so http.Get cannot be used
	// verbatim. Routed through httpDo so tests exercise it without a network.
	httpGetRaw = func(url string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		return httpDoRetrying(req)
	}
	ioReadAll = io.ReadAll
	httpDo    = http.DefaultClient.Do
	osGetenv  = os.Getenv
)

// userAgent identifies bk on every version-listing HTTP request (url listings
// and the GitHub Releases API). Go's default "Go-http-client/2.0" is 403'd by
// some hosts (sourceforge) and the GitHub REST API requires a User-Agent
// outright, so bk always sends its own.
// userAgent is shared with every other HTTP path in bk; see the package.
const userAgent = useragent.String

// ghRelease is the slice of a GitHub Releases API entry bk needs: the human
// display `name` and the underlying git `tag_name` it points at.
type ghRelease struct {
	Name    string `json:"name"`
	TagName string `json:"tag_name"`
}

// Resolve returns both the version string (as it appears upstream, for
// {{version.raw}}) and the raw upstream git tag it was resolved from (for
// {{version.tag}}) selected from a recipe's `versions:` spec, honouring an
// optional constraint ("" or "*" = latest). spec is pantry.Recipe.Versions,
// an `any` unmarshalled from YAML.
//
// The returned tag is the pre-strip candidate that produced the winning
// version: for the github path it is the `refs/tags/`-trimmed tag (e.g.
// "v1.2.3" or "openssl-3.5.0"); for the url/match path it is the matched
// string before any strip. Recipes interpolate it in GitHub release URLs
// like `.../releases/download/{{version.tag}}/{{version.tag}}.tar.gz`.
//
// A list-form `versions:` (an explicit, hardcoded set of candidate versions)
// decodes as a []any of the entries' verbatim scalar text (pantry preserves
// that text so e.g. "3.0" is not coerced to "3"). Those entries ARE the
// candidates: there is no upstream github/url resolution, no strip/ignore, and
// the winning candidate is its own {{version.tag}}.
func Resolve(spec any, constraint string) (string, string, error) {
	switch v := spec.(type) {
	case map[string]any:
		return resolveMap(v, constraint)
	case []any:
		// Same two shapes as List: literal versions, or several source blocks.
		candidates := make([]string, 0, len(v))
		var strips, ignores []*onigmo.Regexp
		var tagOf map[string]string
		for _, e := range v {
			sub, ok := e.(map[string]any)
			if !ok {
				candidates = append(candidates, fmt.Sprint(e))
				continue
			}
			c, tags, s, i, err := gatherCandidates(sub)
			if err != nil {
				return "", "", err
			}
			candidates = append(candidates, c...)
			tagOf = mergeTags(tagOf, tags)
			strips = append(strips, s...)
			ignores = append(ignores, i...)
		}
		return selectVersion(candidates, tagOf, strips, ignores, constraint)
	default:
		return "", "", fmt.Errorf("versions: unsupported version spec %T", spec)
	}
}

// resolveMap handles the github/url map form of `versions:`, listing upstream
// tags (or matching an upstream listing) and selecting via the loose semver.
func resolveMap(m map[string]any, constraint string) (string, string, error) {
	candidates, tagOf, strips, ignores, err := gatherCandidates(m)
	if err != nil {
		return "", "", err
	}
	return selectVersion(candidates, tagOf, strips, ignores, constraint)
}

// gatherCandidates collects EVERY raw candidate version string for the
// github/gitlab/npm/url map form of `versions:` (before any strip/ignore or
// semver parse), together with the recipe's compiled strip and ignore regexes.
// It is the single source of the per-source listing logic shared by Resolve
// (which then picks the max satisfying a constraint) and List (which returns
// them all). Callers apply strips/ignores via selectVersion or listVersions.
// tagOf maps a candidate back to the upstream git tag it came from, and is
// populated ONLY where the two differ: the `github: owner/repo/releases` form,
// which lists a release's human display NAME. Everywhere else the candidate is
// the tag, and a nil map says exactly that.
func gatherCandidates(m map[string]any) (candidates []string, tagOf map[string]string, strips, ignores []*onigmo.Regexp, err error) {
	strips, err = regexList(m["strip"])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ignores, err = regexList(m["ignore"])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	switch {
	case m["github"] != nil:
		gh, _ := m["github"].(string)
		// The github spec routes to one of two upstream listings: bare
		// owner/repo (or .../tags) lists git TAGS via go-git, while
		// owner/repo/releases lists Release entries via the REST API (release
		// `name`, or `tag_name` for the .../releases/tags form).
		mode := githubMode(gh)
		if mode == ghTags {
			repoURL, err := githubRepoURL(gh)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			tags, err := gitLsRemoteTags(repoURL)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			for _, t := range tags {
				candidates = append(candidates, strings.TrimPrefix(t, "refs/tags/"))
			}
		} else {
			owner, repo, err := githubOwnerRepo(gh)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			rels, err := ghListReleases(githubReleasesURL(owner, repo))
			if err != nil {
				return nil, nil, nil, nil, err
			}
			useTag := mode == ghReleaseTags
			for _, r := range rels {
				name := r.Name
				if useTag {
					name = r.TagName
				} else if name == "" {
					// A release with an empty display name falls back to its
					// git tag_name (mirrors brewkit's release-name handling).
					name = r.TagName
				}
				candidates = append(candidates, name)
				// The display name is what makes this listing worth using — ICU
				// names a release "76.1" and tags it `release-76-1` — but the
				// name is NOT what a download URL needs. Remember the tag each
				// candidate came from so {{version.tag}} means what it says.
				if !useTag && r.TagName != "" && r.TagName != name {
					if tagOf == nil {
						tagOf = map[string]string{}
					}
					tagOf[name] = r.TagName
				}
			}
		}
	case m["gitlab"] != nil:
		gl, _ := m["gitlab"].(string)
		repoURL, err := gitlabRepoURL(gl)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tags, err := gitLsRemoteTags(repoURL)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		for _, t := range tags {
			candidates = append(candidates, strings.TrimPrefix(t, "refs/tags/"))
		}
	case m["npm"] != nil:
		pkg, _ := m["npm"].(string)
		body, err := httpGet(npmRegistryURL(pkg))
		if err != nil {
			return nil, nil, nil, nil, err
		}
		var doc struct {
			Versions map[string]json.RawMessage `json:"versions"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("versions: npm %s: %w", pkg, err)
		}
		for v := range doc.Versions {
			candidates = append(candidates, v)
		}
	case m["url"] != nil:
		u, _ := m["url"].(string)
		matchRaw, _ := m["match"].(string)
		if u == "" || matchRaw == "" {
			return nil, nil, nil, nil, fmt.Errorf("versions: url spec needs both url and match")
		}
		re, err := compileDelim(matchRaw)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		body, err := httpGet(u)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		candidates = re.FindAllString(body, -1)
	default:
		return nil, nil, nil, nil, fmt.Errorf("versions: spec has neither github nor url")
	}
	return candidates, tagOf, strips, ignores, nil
}

// VersionTag pairs a resolved version string (post-strip, v-normalised, as
// {{version.raw}}) with the pre-strip upstream tag it was resolved from (as
// {{version.tag}}) — the same two values Resolve returns for a single version.
type VersionTag struct {
	Version string
	Tag     string
}

// List returns EVERY candidate version from a recipe's `versions:` spec —
// github/gitlab tags, an url+match listing, npm registry keys, or a hardcoded
// list — with each candidate stripped, CalVer-normalised, ignore-filtered and
// parsed by the loose semver; unparseable candidates are dropped. The result is
// deduped by resolved version and sorted DESCENDING (newest first). The spec
// semantics are identical to Resolve's; List simply keeps all survivors instead
// of picking the max satisfying a constraint.
func List(spec any) ([]VersionTag, error) {
	var (
		candidates      []string
		tagOf           map[string]string
		strips, ignores []*onigmo.Regexp
	)
	switch v := spec.(type) {
	case map[string]any:
		var err error
		candidates, tagOf, strips, ignores, err = gatherCandidates(v)
		if err != nil {
			return nil, err
		}
	case []any:
		// A list holds EITHER literal version strings, or several source blocks
		// -- kernel.org/linux-headers lists one {url, match, strip} per kernel
		// series. Stringifying a block yielded "map[match:... url:...]", which
		// matches nothing, so every such recipe failed with "no candidate version
		// matched" however healthy its sources were.
		for _, e := range v {
			sub, ok := e.(map[string]any)
			if !ok {
				candidates = append(candidates, fmt.Sprint(e))
				continue
			}
			c, tags, s, i, err := gatherCandidates(sub)
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, c...)
			tagOf = mergeTags(tagOf, tags)
			strips = append(strips, s...)
			ignores = append(ignores, i...)
		}
	default:
		return nil, fmt.Errorf("versions: unsupported version spec %T", spec)
	}
	return listVersions(candidates, tagOf, strips, ignores)
}

// listVersions applies strip then ignore to each candidate, parses the
// survivors with the loose semver (dropping unparseable ones), dedups by
// resolved version string, and returns every distinct VersionTag sorted
// descending. The Tag is the raw pre-strip candidate (the upstream git tag /
// listing match), matching Resolve's version.tag semantics.
func listVersions(candidates []string, tagOf map[string]string, strips, ignores []*onigmo.Regexp) ([]VersionTag, error) {
	type entry struct {
		v  *semver.Version
		vt VersionTag
	}
	var entries []entry
	seen := map[string]bool{}
	for _, c := range candidates {
		s := c
		for _, re := range strips {
			s = re.ReplaceAllString(s, "")
		}
		s = calverToDotted(s)
		if matchesAny(ignores, s) {
			continue
		}
		v, err := semver.ParseVersion(s)
		if err != nil {
			continue
		}
		ver := dropVPrefix(s)
		if seen[ver] {
			continue
		}
		seen[ver] = true
		tag := c
		if t, ok := tagOf[tag]; ok {
			tag = t
		}
		entries = append(entries, entry{v: v, vt: VersionTag{Version: ver, Tag: tag}})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("versions: no candidate version matched")
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].v.Compare(entries[j].v) > 0
	})
	out := make([]VersionTag, len(entries))
	for i, e := range entries {
		out[i] = e.vt
	}
	return out, nil
}

// selectVersion applies strip (remove) then ignore (discard) to each
// candidate, parses the survivors with the loose semver, and returns both the
// (post-strip, v-normalised) version string of the max version satisfying
// constraint and the raw pre-strip candidate that produced it (the upstream
// git tag, for {{version.tag}}).
// calverDashRE matches an all-numeric, dash-separated version — a date-style
// CalVer such as 2025-08-12 (or 2024-1) — with no other characters.
var calverDashRE = regexp.MustCompile(`^\d+(-\d+)+$`)

// calverToDotted rewrites such a CalVer to dotted form (2025-08-12 → 2025.08.12)
// so the loose semver parses it; semver otherwise reads the first '-' as the
// start of a pre-release and the version fails to parse. Zero-padding is kept so
// {{version.raw}} round-trips (recipes map dots↔dashes, e.g. ca-certs does
// `tr . -` to rebuild cacert-YYYY-MM-DD.pem). Non-CalVer strings are unchanged,
// so this can only rescue candidates that would otherwise be skipped.
func calverToDotted(s string) string {
	if calverDashRE.MatchString(s) {
		return strings.ReplaceAll(s, "-", ".")
	}
	return s
}

// npmRegistryURL builds the npm registry document URL for a package. A scoped
// name (@scope/name) must have its slash percent-encoded (@scope%2Fname); an
// unscoped name is used as-is.
func npmRegistryURL(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		pkg = strings.Replace(pkg, "/", "%2F", 1)
	}
	return "https://registry.npmjs.org/" + pkg
}

func selectVersion(candidates []string, tagOf map[string]string, strips, ignores []*onigmo.Regexp, constraint string) (string, string, error) {
	var rng *semver.Range
	if constraint != "" && constraint != "*" {
		r, err := semver.ParseRange(constraint)
		if err != nil {
			return "", "", fmt.Errorf("versions: bad constraint %q: %w", constraint, err)
		}
		rng = r
	}

	var best *semver.Version
	var bestStr, bestTag string
	for _, c := range candidates {
		s := c
		for _, re := range strips {
			s = re.ReplaceAllString(s, "")
		}
		s = calverToDotted(s)
		if matchesAny(ignores, s) {
			continue
		}
		v, err := semver.ParseVersion(s)
		if err != nil {
			continue
		}
		if rng != nil && !rng.Satisfies(v) {
			continue
		}
		if best == nil || v.Compare(best) > 0 {
			best, bestStr, bestTag = v, s, c
		}
	}
	if best == nil {
		return "", "", fmt.Errorf("versions: no candidate version matched")
	}
	if t, ok := tagOf[bestTag]; ok {
		bestTag = t
	}
	return dropVPrefix(bestStr), bestTag, nil
}

// mergeTags folds one source block's candidate→tag map into the accumulated
// one. A multi-source `versions:` list can mix a releases block with a tags
// block, and only the former contributes entries.
func mergeTags(into, from map[string]string) map[string]string {
	if len(from) == 0 {
		return into
	}
	if into == nil {
		into = map[string]string{}
	}
	for k, v := range from {
		into[k] = v
	}
	return into
}

// dropVPrefix strips a leading "v" before a digit ("v5.8.3" -> "5.8.3"), matching
// pkgx's tag normalisation (dist bottles are tagged without the v). Recipes whose
// `strip:` already removes the v are unaffected; this only catches github-tag
// specs that don't.
func dropVPrefix(s string) string {
	if len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
		return s[1:]
	}
	return s
}

// githubListMode classifies a `github:` spec by which upstream listing it
// names: git tags, Release display names, or Release tag_names.
type githubListMode int

const (
	ghTags         githubListMode = iota // owner/repo or owner/repo/tags
	ghReleaseNames                       // owner/repo/releases
	ghReleaseTags                        // owner/repo/releases/tags
)

// githubMode reports which upstream listing a `github:` spec selects, matching
// brewkit's semantics: a bare owner/repo (or a decorative .../tags suffix)
// lists git tags; a /releases path component lists the REST Releases API's
// display names; /releases/tags lists those releases' tag_names. Only the
// suffix after owner/repo is inspected, so a repo literally named "releases"
// still lists tags.
func githubMode(gh string) githubListMode {
	parts := strings.Split(gh, "/")
	for i := 2; i < len(parts); i++ {
		if parts[i] == "releases" {
			if i+1 < len(parts) && parts[i+1] == "tags" {
				return ghReleaseTags
			}
			return ghReleaseNames
		}
	}
	return ghTags
}

// githubOwnerRepo extracts the owner and repo from a `github:` value, accepting
// the bare owner/repo form and any of the owner/repo/tags, owner/repo/releases
// and owner/repo/releases/tags suffixes.
func githubOwnerRepo(gh string) (owner, repo string, err error) {
	parts := strings.Split(gh, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("versions: invalid github spec %q", gh)
	}
	return parts[0], parts[1], nil
}

// githubRepoURL derives the git clone URL https://github.com/<owner>/<repo>
// from a `github:` value (used for the tag-listing path via gitLsRemoteTags).
func githubRepoURL(gh string) (string, error) {
	owner, repo, err := githubOwnerRepo(gh)
	if err != nil {
		return "", err
	}
	return "https://github.com/" + owner + "/" + repo, nil
}

// githubReleasesURL builds the REST Releases API URL for a repo, capped at the
// 100 newest releases (page 1) — ample for latest-version resolution.
func githubReleasesURL(owner, repo string) string {
	return "https://api.github.com/repos/" + owner + "/" + repo + "/releases?per_page=100"
}

// gitlabRepoURL turns a pantry `gitlab:` spec into a clone URL. The spec is
// "[host:]group/project[/…][/tags]": an optional "host:" prefix selects a
// self-hosted GitLab (default gitlab.com), a trailing "/tags" is decorative, and
// the remaining path — which may be nested through subgroups — is the project.
// GitLab serves tags over the same `git ls-remote` as GitHub, so only the URL
// differs.
func gitlabRepoURL(gl string) (string, error) {
	host, path := "gitlab.com", gl
	if i := strings.IndexByte(gl, ':'); i >= 0 {
		host, path = gl[:i], gl[i+1:]
	}
	path = strings.Trim(strings.TrimSuffix(strings.Trim(path, "/"), "/tags"), "/")
	if host == "" || !strings.Contains(path, "/") {
		return "", fmt.Errorf("versions: invalid gitlab spec %q", gl)
	}
	return "https://" + host + "/" + path, nil
}

// regexList compiles a strip/ignore value, which may be absent, a single
// /regex/ (or bare) string, or a list of them.
func regexList(v any) ([]*onigmo.Regexp, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		re, err := compileDelim(t)
		if err != nil {
			return nil, err
		}
		return []*onigmo.Regexp{re}, nil
	case []any:
		out := make([]*onigmo.Regexp, 0, len(t))
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("versions: strip/ignore entry not a string: %T", x)
			}
			re, err := compileDelim(s)
			if err != nil {
				return nil, err
			}
			out = append(out, re)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("versions: invalid strip/ignore %T", v)
	}
}

// compileDelim compiles s as a Go regexp, stripping surrounding /.../ slashes
// (pkgx's regex delimiters) first.
func compileDelim(s string) (*onigmo.Regexp, error) {
	p := s
	if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
		p = p[1 : len(p)-1]
	}
	re, err := onigmo.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("versions: bad regex %q: %w", s, err)
	}
	return re, nil
}

// matchesAny reports whether s matches any of the regexes.
func matchesAny(res []*onigmo.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// notFoundish matches what a Git host says when a repository is not there. It
// is the same answer it gives for a private one — GitHub 404s both, so the
// client asks for credentials and reports the refusal.
var notFoundish = regexp.MustCompile(`(?i)authentication required|repository not found`)

// describeRemoteErr renames the one ls-remote failure that misleads.
//
// A recipe pointing at a repository that has been deleted or renamed fails as
//
//	versions: ls-remote https://github.com/jetporch/jetporch:
//	  authentication required: Repository not found.
//
// which reads as a credentials problem in CI, and sends the reader to look at
// tokens. It is not: GitHub answers 404 for a missing repository AND for a
// private one, git cannot tell them apart, and asks for a password. Six of
// eighty-one failures in one factory run wore that label; every one was a
// pantry recipe whose upstream had gone away.
func describeRemoteErr(err error) error {
	if err == nil || !notFoundish.MatchString(err.Error()) {
		return err
	}
	return fmt.Errorf("%w — the repository does not exist, or is private (a Git host answers 404 for both, so the client asks for credentials)", err)
}
