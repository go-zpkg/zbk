package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// runDepsplit implements `bk depsplit`: find the recipes that name ONE project
// in BOTH dependency lists with constraints that select DIFFERENT versions.
//
// ⛔ WHY THAT IS A DEFECT AND NOT A STYLE. build.go keeps the two lists apart
// deliberately — EvalLinkDeps is "the set a build LINKS against: the recipe's
// own runtime dependencies, and nothing else", EvalToolDeps is the build
// dependencies, whose "version constraints are nobody else's business". That
// separation is what lets qt.io build: unicode.org ^71 to link, ^73 to run
// nodejs, two ICUs that are never in one process.
//
// The case it does not cover is the SAME project in both. Then two versions
// of one library land in one build environment, and which supplies headers
// and which supplies libraries is decided by search order rather than by the
// recipe. Measured on protobuf.dev 36.2 (darwin/aarch64, 2026-10-26):
//
//	dependencies:        abseil.io: "*"        -> 20260817  (headers)
//	build.dependencies:  abseil.io: ^20260526  -> 20260526  (libraries)
//	=> ld: "absl::lts_20260817::Mutex::AssertHeld() const", referenced from: …
//	   symbol(s) not found for architecture arm64
//
// When the same disagreement happens to LINK instead of failing it is worse:
// the artifact ships an @rpath reference to the version the headers came from
// while declaring the constraint a consumer will resolve differently. That is
// an uninstallable artifact, published green.
//
// ⛔ THE VERDICT IS "DIFFERENT VERSION", NOT "DIFFERENT TEXT". `*` and `>=1`
// differ as strings and almost never as answers; `*` and ^20260526 differ as
// answers. Only the second is worth a line, so the comparison resolves both
// constraints against what the registry actually carries FOR THIS PLATFORM,
// through artifact's own semver — the code pkgx uses at install, so a
// disagreement reported here is one a build will meet.
func runDepsplit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("depsplit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pantryDir := fs.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout to read recipes from")
	overridesDir := fs.String("overrides", "overrides", `recipe overrides to apply first ("" to skip)`)
	platform := fs.String("platform", envOr("PLATFORM", "linux/x86-64"), "target os/arch")
	failOn := fs.Bool("fail", false, "exit 1 if anything is found")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	osn, arch, _ := strings.Cut(*platform, "/")
	tgt := target.Target{Platform: osn, Arch: arch}

	// Overrides first, like depgaps: the pantry on disk is UPSTREAM, and what
	// the factory builds is the pantry plus our edits. Auditing the unpatched
	// pantry would describe a factory that does not exist — and the first fix
	// for this very class is an override (go-zpkg/packages#375).
	// ⛔ AND A NAMED OVERRIDES DIRECTORY THAT IS NOT THERE IS AN ERROR.
	// logical.LoadDir tolerates an absent directory and returns an empty set,
	// which for this command is the worst possible answer: the audit would
	// run against the UNPATCHED pantry and report, among others, the one
	// instance of this class that is already fixed by an override. An
	// operator who reads a repaired defect in a defect list stops reading the
	// list. Pass -overrides "" to mean it.
	var lset *logical.Set
	if *overridesDir != "" {
		if _, err := osStat(*overridesDir); err != nil {
			fmt.Fprintf(stderr, "depsplit: %s: %v\n", *overridesDir, err)
			fmt.Fprintln(stderr, `depsplit: refusing to audit the UNPATCHED pantry — pass -overrides "" if that is what you want`)
			return 2
		}
		s, err := logical.LoadDir(*overridesDir)
		if err != nil {
			fmt.Fprintln(stderr, "depsplit:", err)
			return 2
		}
		lset = s
	}

	cand, err := depsplitCandidates(lset, *pantryDir, tgt)
	if err != nil {
		fmt.Fprintln(stderr, "depsplit:", err)
		return 1
	}
	fmt.Fprintf(stderr, "depsplit: %d pair(s) named in both lists with differing text; resolving\n", len(cand))

	c, err := newDepsplitRegistry(artifact.DistBase)
	if err != nil {
		fmt.Fprintln(stderr, "depsplit:", err)
		return 1
	}
	found := depsplitResolve(cand, &registryPicker{
		c: c, osn: osn, arch: arch,
		tags: map[string][]string{}, has: map[string]bool{},
		warn: stderr,
	})
	reportSplits(stdout, found, *platform)
	if *failOn && len(found) > 0 {
		return 1
	}
	return 0
}

// Split is one recipe naming one project in both lists, resolved.
type Split struct {
	Recipe  string // the recipe's project directory, e.g. "protobuf.dev"
	Project string // the doubly-named dependency, e.g. "abseil.io"
	Link    string // the runtime (link) constraint, "" when unconstrained
	Tool    string // the build (tool) constraint
	LinkVer string // the version the link constraint selects
	ToolVer string // the version the tool constraint selects
}

// picker answers "newest version of p published HERE that satisfies c", or ""
// if none does. An interface so a test can plant a positive without a
// network: a detector exercised only against the live registry has no
// control, and cannot be shown to SEE the thing it looks for.
type picker interface {
	Pick(project, constraint string) string
}

// depsplitCandidates finds, offline, every (recipe, project) named in both
// lists with constraints that differ as TEXT. Resolution is a separate pass
// because it costs the network, and because the two halves fail differently:
// this one can be complete, that one cannot.
//
// The recipe is the OVERRIDDEN one, the same way the factory reads it.
func depsplitCandidates(set *logical.Set, pantryDir string, tgt target.Target) ([]Split, error) {
	root := filepath.Join(pantryDir, "projects")
	var out []Split
	err := filepathWalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || !recipefile.IsRecipe(d.Name()) {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(p))
		if relErr != nil {
			return nil
		}
		project := filepath.ToSlash(rel)
		rec, loadErr := recipefile.LoadOverridden(set, pantryDir, project)
		if loadErr != nil || rec == nil {
			// A recipe we cannot parse is a different problem, and the schema
			// gate already reports it. Counting it here would be noise.
			return nil
		}
		if !pantry.Supports(rec, tgt.Platform, tgt.Arch) {
			return nil
		}
		link := constraintsOf(build.DepSpecs(rec.Dependencies, tgt))
		tool := constraintsOf(build.DepSpecs(build.BuildDeps(rec), tgt))
		both := make([]string, 0, len(link))
		for proj := range link {
			if _, ok := tool[proj]; ok {
				both = append(both, proj)
			}
		}
		sort.Strings(both)
		for _, proj := range both {
			// Identical text is identical meaning; asking the registry about
			// it would only bury the real ones.
			if link[proj] == tool[proj] {
				continue
			}
			out = append(out, Split{
				Recipe: project, Project: proj,
				Link: link[proj], Tool: tool[proj],
			})
		}
		return nil
	})
	return out, err
}

// constraintsOf turns bk's "project@constraint" specs into project ->
// constraint, with "" for unconstrained. Splitting on the last "@" would be
// wrong for a project whose name contains one; SpecProject is the authority.
func constraintsOf(specs []string) map[string]string {
	m := make(map[string]string, len(specs))
	for _, s := range specs {
		proj := build.SpecProject(s)
		m[proj] = strings.TrimPrefix(strings.TrimPrefix(s, proj), "@")
	}
	return m
}

// depsplitResolve fills in the two versions and keeps only the pairs where
// they genuinely differ.
//
// ⛔ A CONSTRAINT THAT RESOLVES TO NOTHING IS NOT A SPLIT. It is a gap, and
// `bk depgaps` ranks those. Reporting it here would put two populations under
// one heading and make either count meaningless on its own.
func depsplitResolve(in []Split, p picker) []Split {
	var out []Split
	for _, s := range in {
		s.LinkVer = p.Pick(s.Project, s.Link)
		s.ToolVer = p.Pick(s.Project, s.Tool)
		if s.LinkVer == "" || s.ToolVer == "" || s.LinkVer == s.ToolVer {
			continue
		}
		out = append(out, s)
	}
	return out
}

// reportSplits prints the findings, ordered so a diff between two runs reads.
//
// ⛔ THESE ARE CANDIDATES, NOT DEFECTS, and the heading says so. For an
// interpreter named as a runtime dependency — nodejs.org under yarnpkg.com,
// pnpm.io under elizaOS.github.io — two versions in one build is the qt case
// working as designed. The discriminator is whether the doubly-named project
// contributes libraries that are LINKED, which this cannot tell from the
// recipe. Printing a count as if it were a defect count is how a list like
// this stops being read.
func reportSplits(w io.Writer, found []Split, platform string) {
	sort.Slice(found, func(i, j int) bool {
		if found[i].Recipe != found[j].Recipe {
			return found[i].Recipe < found[j].Recipe
		}
		return found[i].Project < found[j].Project
	})
	fmt.Fprintf(w, "%d recipe-dependency pair(s) resolve to two versions in one build (%s)\n", len(found), platform)
	fmt.Fprintf(w, "a pair is a CANDIDATE: harmful when the project is linked, normal when it is a tool\n\n")
	for _, s := range found {
		fmt.Fprintf(w, "%s\n    %s\n", s.Recipe, s.Project)
		fmt.Fprintf(w, "        links against  %-14s -> %s\n", quoteConstraint(s.Link), s.LinkVer)
		fmt.Fprintf(w, "        builds with    %-14s -> %s\n", quoteConstraint(s.Tool), s.ToolVer)
	}
}

func quoteConstraint(c string) string {
	if c == "" {
		return `"*"`
	}
	return `"` + c + `"`
}

// registryPicker answers from the live registry, caching both the tag list
// and the per-version platform check: the candidate list repeats projects
// (abseil.io appears under protobuf, re2 and grpc) and neither answer changes
// during a run.
// depsplitRegistry is the half of the registry this needs, as an interface so
// the resolution pass can be driven without a network — the seam below is how
// every branch of it is reachable from a test.
type depsplitRegistry interface {
	ListTags(project string) ([]string, error)
	HasPlatform(project, version, osn, arch string) (bool, error)
}

var newDepsplitRegistry = func(dist string) (depsplitRegistry, error) {
	return artifact.NewOCIClient(dist)
}

type registryPicker struct {
	c    depsplitRegistry
	osn  string
	arch string
	tags map[string][]string
	has  map[string]bool
	warn io.Writer
}

func (r *registryPicker) Pick(project, constraint string) string {
	tags, ok := r.tags[project]
	if !ok {
		t, err := r.c.ListTags(project)
		if err != nil {
			fmt.Fprintf(r.warn, "depsplit: %s: %v\n", project, err)
			t = nil
		}
		tags = t
		r.tags[project] = tags
	}
	return newestPublished(tags, constraint, func(tag string) bool {
		return r.published(project, tag)
	})
}

func (r *registryPicker) published(project, tag string) bool {
	key := project + "@" + tag
	if v, ok := r.has[key]; ok {
		return v
	}
	has, err := r.c.HasPlatform(project, tag, r.osn, r.arch)
	if err != nil {
		// ⛔ An index we could not read is NOT an absence. Saying "no" here
		// would walk on to an older version and report a difference that is
		// an artefact of a failed read. Say so, and treat it as present so
		// the pair is judged on versions rather than on connectivity.
		fmt.Fprintf(r.warn, "depsplit: %s %s: %v (treated as published)\n", project, tag, err)
		has = true
	}
	r.has[key] = has
	return has
}

// newestPublished picks the version a resolver would, so a difference
// reported here is a difference a build will experience.
//
// ⛔ THE ORDERING IS artifact's. VersionsFromTags returns the versions a client
// would consider, OLDEST FIRST, after dropping artifacts built against another
// glibc flavour and folding "1.0", "1.0.0" and "v1.0.0" into one candidate.
// Re-deriving that locally is how pkgx's `request` came to report nodejs
// 26.8.1 an hour after 26.12.1 shipped: as text, "8" > "1".
//
// ⛔ AND A TAG IS NOT A PLATFORM. The tag list is one list for every
// platform. Without `published`, this reported github.com/awslabs/dynein as
// linking openssl.org 1.1.1w on linux/x86-64 — a version tagged, and
// published for darwin/aarch64 alone, which no build there can obtain. The
// judge has to count the way the subject does.
func newestPublished(tags []string, constraint string, published func(tag string) bool) string {
	vers := artifact.VersionsFromTags(tags)
	for i := len(vers) - 1; i >= 0; i-- {
		if constraint != "" && !vers[i].Satisfies(constraint) {
			continue
		}
		if t := vers[i].RegistryTag(); published(t) {
			return t
		}
	}
	return ""
}
