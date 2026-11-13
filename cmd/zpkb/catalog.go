package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-attest/sign"
	"github.com/go-zpkg/bottle"
	"github.com/go-zpkg/zpkb/build"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/pantry"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

// runCatalog builds the catalogue a browser reads, and optionally publishes
// it.
//
// # WHY THIS EXISTS
//
// An anonymous client cannot enumerate ghcr: `/v2/_catalog` answers 403 and
// only per-project tag lists are served. So `pkgx ls` and `gnu.org/<TAB>`
// have nothing to read unless the registry carries a catalogue of its own.
// bottle#114 made it an ordinary bottle; this is what fills it.
//
// # NAMES WITHOUT A SWEEP, BY DEFAULT
//
// The pantry has ~1900 projects. Asking the registry which versions each one
// has published is ~1900 requests, and this repository has twice paid for
// treating a per-project loop as free. The default therefore reads the
// pantry and the overlay and nothing else: no network, and the catalogue
// says what projects EXIST.
//
// That is not a degraded answer for the job it has. Tab-completion needs
// NAMES; a version beside a candidate is a courtesy. `--versions` opts into
// the sweep for a run that wants it, and says how many requests it will make
// before it makes them.
//
// # PUBLISHED SIGNED
//
// `--publish` pushes it through the same path `bk publish` uses, with the
// same SBOM, provenance and cosign signature. A client with ZPKG_VERIFY on
// — the default — refuses an unsigned catalogue, and should: the catalogue
// is the list of names a person then TYPES, so whoever decides its contents
// decides what `<TAB>` offers. With no key (`--sign`, else $SIGNING_KEY) it
// still publishes, because the seed registry in a sovereign build has none,
// and says in one line what a verifying client will do with the result.
func runCatalog(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("catalog", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pantryDir := fs.String("pantry", envOr("PANTRY", "pantry"), "pantry checkout dir")
	overlayDir := fs.String("overlay", envOr("PANTRY_OVERLAY_DIR", ""), "an overlay checkout read beside the pantry")
	platform := fs.String("platform", envOr("PLATFORM", "linux/x86-64"), "the platform this catalogue is FOR")
	out := fs.String("o", "", "write the JSON here instead of stdout")
	overridesDir := fs.String("overrides", envOr("OVERRIDES", ""), "directory of *.hcl logical recipe overrides, applied as the factory applies them")
	publish := fs.Bool("publish", false, "push it to $ZPKG_DIST as a bottle, for this platform")
	withVersions := fs.Bool("versions", false, "ask the registry what each project has published (one request per project)")
	signKey := fs.String("sign", "", "sign the published catalogue with this go-attest/sign secret key file (else $SIGNING_KEY)")
	var extra stringList
	fs.Var(&extra, "recipes", "a FLAT recipe tree (<dir>/<project>/package.yml, e.g. wasip1/recipes) whose projects are named too, and whose recipe WINS over the pantry's for a project in both (it is the recipe for this platform); repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	osn, arch, ok := strings.Cut(*platform, "/")
	if !ok {
		fmt.Fprintf(stderr, "catalog: --platform wants os/arch, not %q\n", *platform)
		return 2
	}

	projects, err := catalogProjects(*pantryDir, *overlayDir, extra...)
	if err != nil {
		fmt.Fprintln(stderr, "catalog:", err)
		return 1
	}
	if len(projects) == 0 {
		// An empty catalogue would be published and believed. A pantry that
		// read as empty is a mistyped path far more often than an empty
		// pantry, and the two must not have the same outcome.
		fmt.Fprintf(stderr, "catalog: no projects under %q — an empty catalogue is not a result\n", *pantryDir)
		return 1
	}

	cat := bottle.Catalog{Generated: catalogNow().UTC().Format(time.RFC3339)}
	lset, err := logical.LoadDir(*overridesDir)
	if err != nil {
		fmt.Fprintln(stderr, "catalog:", err)
		return 2
	}
	tgt := target.Target{Platform: osn, Arch: arch}
	var noRecipe int
	for _, p := range projects {
		e := bottle.CatalogProject{Project: p}
		// The RUNTIME dependencies, reduced for this platform, so a reader
		// can walk the tree with no pantry and no network (bottle#117).
		// Still no requests: these come off the recipe already on disk.
		//
		// ⛔ A --recipes TREE IS THE AUTHORITY FOR ITS PLATFORM, NOT A
		// FALLBACK (go-zpkg/bk#376). #375 read it only when the pantry and
		// overlay had nothing, so for a project in BOTH the HOST recipe
		// described the lane's bottle: zlib.net published minigzip with no
		// `provides` (the host recipe is a library), filippo.io/age listed
		// age-keygen (the lane builds ./cmd/age only), lua.org depended on
		// readline (the lane builds Lua's generic `ansi` platform). Where the
		// tree has the project, its recipe is read whole -- provides and
		// dependencies together, never a mix of two builds. The rule for the
		// caller: pass --recipes only for a platform whose tree IS its recipe
		// set; a tree that is not would now override the pantry.
		var (
			r   *pantry.Recipe
			err error
		)
		if xr, found := extraRecipe(extra, p); found {
			r = xr
		} else {
			r, _, err = recipeLoader(lset, *overlayDir, *pantryDir, p)
		}
		if err == nil && r != nil {
			for _, spec := range build.DepSpecs(r.Dependencies, tgt) {
				if n := depName(spec); n != "" {
					e.Deps = append(e.Deps, n)
				}
			}
			sort.Strings(e.Deps)
			// What the project IS, for a search that is more than a
			// prefix. `nix search`, `guix search` and `spack list -s` all
			// look in the description as well as the name, because the
			// person who does not know a package's name is exactly the
			// person searching. These fields have sat in pantry.Recipe
			// with no reader anywhere.
			e.Summary = summaryOf(r)
			// The commands, which is what a search can actually work on
			// here: 1592 of 1907 recipes declare them against 6 that
			// describe themselves in prose.
			e.Provides = build.ProvidedCommands(r.Provides, tgt)
		} else {
			// Counted, not silent. A project the walk NAMED and the reader
			// cannot load is a hole in the dependency half of the
			// catalogue, and a catalogue that hid it would show those
			// projects as having no dependencies at all — which is a
			// statement, and a false one.
			noRecipe++
		}
		cat.Projects = append(cat.Projects, e)
	}
	if noRecipe > 0 {
		fmt.Fprintf(stderr, "catalog: %d project(s) named but unreadable — listed with no dependencies\n", noRecipe)
	}
	// Said out loud, because it is what decides whether `pkgx search` is
	// worth anything: a catalogue where almost nothing carries a summary
	// gives a search that finds almost nothing, and the number belongs in
	// front of whoever publishes it rather than in a reader's
	// disappointment.
	summaries := 0
	for _, p := range cat.Projects {
		if p.Summary != "" {
			summaries++
		}
	}
	cmds := 0
	for _, p := range cat.Projects {
		if len(p.Provides) > 0 {
			cmds++
		}
	}
	fmt.Fprintf(stderr, "catalog: %d of %d project(s) name their commands, %d describe themselves\n", cmds, len(cat.Projects), summaries)
	if *withVersions {
		// The count has to stay true as the work grows. It was "one
		// request each" when a tag listing was the whole of it; a
		// platform check costs at least one more, and up to
		// platformProbes for a project this architecture has nothing
		// for. Saying the old number would understate it by half.
		fmt.Fprintf(stderr, "catalog: asking the registry about %d project(s): a tag listing each, plus 1 to %d platform checks\n",
			len(cat.Projects), platformProbes)
		fillVersions(cat.Projects, osn, arch, func(s string) { fmt.Fprintln(stderr, s) })
	}

	body, err := marshalCatalog(cat)
	if err != nil {
		fmt.Fprintln(stderr, "catalog:", err)
		return 1
	}
	switch {
	case *publish:
		kp, err := signingKey(*signKey)
		if err != nil {
			fmt.Fprintln(stderr, "catalog: signing key:", err)
			return 1
		}
		if err := publishCatalogSigned(bottle.DistBase, cat, osn, arch, kp); err != nil {
			fmt.Fprintln(stderr, "catalog: publish:", err)
			return 1
		}
		note := " +signature"
		if kp == nil {
			// Stated as a consequence, not as a warning about style. A
			// client with ZPKG_VERIFY on — the default — refuses an
			// unsigned catalogue, so this publish produces something
			// only the seed registry can read.
			note = " UNSIGNED: a client with ZPKG_VERIFY on will refuse this"
		}
		fmt.Fprintf(stderr, "catalog: %d project(s) → %s %s/%s (+SBOM +provenance%s)\n",
			len(cat.Projects), bottle.DistBase, osn, arch, note)
	case *out != "":
		if err := osWriteFile(*out, body, 0o644); err != nil {
			fmt.Fprintln(stderr, "catalog:", err)
			return 1
		}
		fmt.Fprintf(stderr, "catalog: %d project(s) → %s\n", len(cat.Projects), *out)
	default:
		fmt.Fprint(stdout, string(body))
	}
	return 0
}

// publishCatalogSigned pushes the catalogue the way a bottle is pushed:
// SBOM, provenance, and — when a key is to hand — a cosign signature.
//
// bottle.PublishCatalog pushes the bare tarball, which is what the seed
// registry inside a sovereign build wants, and was all that existed when
// nothing checked. A client now refuses an unsigned catalogue by default,
// and rightly: the catalogue is the list of names a person then TYPES, so
// deciding its contents is deciding what `<TAB>` offers.
//
// It goes out through ociPush, the SAME push `bk publish` and the factory
// use, with the same referrer builder: the catalogue is not a special
// artefact and must not get a trust path of its own, because a second path
// is the thing that was wrong here in the first place.
func publishCatalogSigned(dist string, cat bottle.Catalog, osn, arch string, kp *sign.Keypair) error {
	tgz, err := catalogTarball(cat)
	if err != nil {
		return err
	}
	// The catalogue is generated by bk from the registry, not built from a
	// recipe: it has no source archive and no build environment, and says so
	// by passing neither rather than by inventing one.
	// Nor an origin: the catalogue is not a build at all, so "was host
	// tooling involved" has no answer to give rather than an answer of "no".
	refs, err := buildReferrers(bottle.CatalogProjectName, bottle.CatalogVersion,
		osn, arch, tgz, build.SourceRef{}, nil, factoryTime(), kp, provOrigin{})
	if err != nil {
		return err
	}
	_, err = ociPush(dist, bottle.CatalogProjectName, bottle.CatalogVersion,
		osn, arch, tgz, bottle.ExtTarGz, refs, nil)
	return err
}

// seams, so a test needs neither a clock nor a registry.
var (
	catalogNow      = time.Now
	versionsFor     = bottle.VersionsForSourced
	publishedTagFor = bottle.PublishedTagFor
	marshalCatalog  = bottle.MarshalCatalog
	catalogTarball  = bottle.CatalogTarball
	signingKey      = factorySigningKey
)

// fillVersions asks the registry what THIS platform can actually install.
//
// Two things it must not do, and did:
//
// It must not borrow. bottle.VersionsFor falls back to the upstream dist
// for a project this registry has never published, which is right for a
// resolver and wrong here: a catalogue that listed dist.pkgx.dev's version
// beside doxygen.nl would have offered a version nobody can install.
// "Available" is a claim about ONE registry, so a list from another one is
// not an answer to it.
//
// It must not claim a platform it has not checked. A tag listing spans
// every architecture, so the newest tag is not necessarily installable for
// the one being published: a mirror wave that lands x86-64 publishes a tag
// s390x cannot use. The version recorded is therefore the newest one this
// platform really carries, probed newest-first and stopped at the first
// hit, so the number a reader sees is the one they would get.
//
// A project with no version left after that is still NAMED, with no
// version and no platform beside it. That is the answer, not a gap:
// somebody looking for doxygen.nl should learn it exists and has no bottle
// here, rather than that it does not exist.
//
// Failures are per project and are WARNED, not fatal: a catalogue missing
// one project's versions is still a catalogue, and a registry hiccup
// two thousand requests in must not throw the other 1999 away.
func fillVersions(projects []bottle.CatalogProject, osn, arch string, warn func(string)) {
	for i := range projects {
		vs, ours, err := versionsFor(projects[i].Project, osn, arch)
		if err != nil {
			warn(fmt.Sprintf("catalog: %s: %v", projects[i].Project, err))
			continue
		}
		if !ours || len(vs) == 0 {
			continue
		}
		v, ok, err := newestHere(projects[i].Project, vs, osn, arch)
		if err != nil {
			warn(fmt.Sprintf("catalog: %s: %v", projects[i].Project, err))
			continue
		}
		if !ok {
			continue
		}
		projects[i].Versions = []string{v}
		projects[i].Platforms = []string{osn + "/" + arch}
	}
}

// summaryOf is the one line a search matches against.
//
// `summary` first, because it is the field written to be one line.
// `description` is the fallback and is cut at its first sentence or at
// summaryMax: a catalogue is a 100 KB artefact every reader downloads, and
// some descriptions are paragraphs — carrying them whole would multiply its
// size for text nothing displays.
//
// display-name is deliberately NOT folded in. It is usually the project
// name with different capitalisation, so a search would match it twice and
// rank that above a real hit in a summary.
func summaryOf(r *pantry.Recipe) string {
	s := strings.TrimSpace(r.Summary)
	if s == "" {
		s = strings.TrimSpace(r.Description)
	}
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i > 0 && i < summaryMax {
		return s[:i]
	}
	if len(s) > summaryMax {
		// Cut at a word, not mid-word: a truncated token is a token a
		// search will never match and a reader cannot read.
		if j := strings.LastIndex(s[:summaryMax], " "); j > 0 {
			return s[:j] + "…"
		}
		return s[:summaryMax] + "…"
	}
	return s
}

// summaryMax bounds one summary. 200 characters is about two printed lines
// at the width `pkgx search` uses, and 1900 of them is ~380 KB worst case
// against a catalogue that is 100 KB today — which is why it is bounded at
// all rather than left to the pantry.
const summaryMax = 200

// platformProbes bounds how far down a project's versions the platform
// check will walk.
//
// Without a bound, a project with forty tags and no bottle for this
// architecture — which is the normal state of a young lane — costs forty
// requests to learn nothing, and there are two thousand projects. The
// ordinary case costs ONE: the newest version is published everywhere it
// is published at all, and the walk stops at the first hit.
const platformProbes = 5

// newestHere is the newest version this platform can actually install.
//
// vs arrives ascending in VERSION order, which is why this walks the slice
// backwards instead of sorting. The code here used to `sort.Reverse` the
// raw strings, and a string sort puts "1.9" above "1.10" — so the version
// a reader was shown could be an old one wearing the newest's place.
func newestHere(project string, vs []bottle.Ver, osn, arch string) (string, bool, error) {
	for i, probes := len(vs)-1, 0; i >= 0 && probes < platformProbes; i, probes = i-1, probes+1 {
		_, ok, err := publishedTagFor(project, vs[i], osn, arch)
		if err != nil {
			return "", false, err
		}
		if ok {
			return vs[i].Raw, true, nil
		}
	}
	return "", false, nil
}

// catalogProjects is every project named by the pantry or the overlay.
//
// The UNION, because both are real: the factory builds from the pantry with
// overrides applied, and a consumer resolves from the overlay. A project in
// only one of them is still a project somebody can ask for, and a catalogue
// that read one half would complete onto a name the other half cannot build
// — or hide one it can.
//
// extraDirs are FLAT recipe trees — <dir>/<project>/package.yml, the layout
// `bk build --recipe` is given, with no `projects/` level — whose projects
// are named too. A platform lane may build a project that neither the pantry
// nor the overlay carries (wasip1/recipes/github.com/simdjson/simdjson in
// go-zpkg/packages): without this the catalogue for that platform could not
// name a bottle that is published and installable (go-zpkg/packages#387).
func catalogProjects(pantryDir, overlayDir string, extraDirs ...string) ([]string, error) {
	seen := map[string]bool{}
	roots := []string{pantryDir, overlayDir}
	for _, root := range roots {
		if root == "" {
			continue
		}
		base := filepath.Join(root, "projects")
		err := walkRecipes(base, seen)
		// A pantry that cannot be walked at all is reported; an overlay that
		// is simply absent is not. The first is a mistyped path, the second
		// is the ordinary case.
		if err != nil && root == pantryDir {
			return nil, err
		}
	}
	for _, base := range extraDirs {
		// Named explicitly on the command line, so a tree that cannot be
		// walked is an error, not the ordinary absent-overlay case.
		if err := walkRecipes(base, seen); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// extraRecipe reads a project's recipe from the first flat tree that has one.
func extraRecipe(extraDirs []string, project string) (*pantry.Recipe, bool) {
	for _, dir := range extraDirs {
		for _, n := range recipefile.Names {
			if r, err := recipefile.LoadFile(filepath.Join(dir, filepath.FromSlash(project), n)); err == nil {
				return r, true
			}
		}
	}
	return nil, false
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// walkRecipes adds to seen every project directory under base that holds a
// recipe file.
func walkRecipes(base string, seen map[string]bool) error {
	{
		err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			// An error AT THE ROOT is the whole walk failing and is returned;
			// one further down is a single unreadable directory and is
			// skipped. Swallowing both is how a mistyped pantry path came to
			// report "no projects" -- the message for an empty pantry -- and
			// the coverage gate is what showed it, by leaving the branch that
			// reports a read failure with nothing able to reach it.
			if err != nil {
				if p == base {
					return err
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			switch d.Name() {
			case "package.yml", "package.yaml", "package.hcl":
			default:
				return nil
			}
			// TrimPrefix rather than filepath.Rel: p is under base by
			// construction, and Rel's error arm is a branch nothing can
			// reach -- which this gate is right to refuse.
			rel := strings.TrimPrefix(filepath.Dir(p), base+string(filepath.Separator))
			seen[filepath.ToSlash(rel)] = true
			return nil
		})
		return err
	}
}
