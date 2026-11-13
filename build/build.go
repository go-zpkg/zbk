// Package build holds the orchestration helpers that turn a parsed recipe into
// a runnable build: the dependency closure (recipe deps reduced for the target),
// the ambient base toolchain brewkit provides, a sanitized run environment, and
// the autotools maintainer-mode defeat. These were distilled from proving bk on
// real packages (zlib native, zlib→windows cross, wget with openssl).
package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-zpkg/artifact"
	"github.com/go-zpkg/zpkb/logical"
	"github.com/go-zpkg/zpkb/moustache"
	"github.com/go-zpkg/zpkb/recipefile"
	"github.com/go-zpkg/zpkb/target"
)

var (
	// Derived from target, which is the one table of platforms and arches.
	platforms = setOf(target.Platforms())
	arches    = setOf(target.Arches())
	// Derived from the two maps rather than restated beside them. A recipe key
	// is read through BOTH -- the regex for `linux/s390x`, the map for a bare
	// `s390x` -- so a literal here that fell behind would make one spelling of
	// the same key legal and the other unknown. An unknown key is not an error:
	// platformKey returns ok=false, reduceDepMap copies it through as a project
	// name, and the recipe acquires a dependency on a project called "s390x".
	osArchDepRE = regexp.MustCompile(`^(` + alternation(platforms) + `)/(` + alternation(arches) + `)$`)
)

func setOf(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// alternation renders a set as a regex alternation. Sorted for a stable
// pattern; the expression it goes into is anchored and separated by a slash,
// so the order carries no meaning beyond that.
func alternation(set map[string]bool) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, regexp.QuoteMeta(k))
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

// reduceDepMap flattens a recipe dependency map (project → constraint, with
// optional platform-keyed sub-maps) to project → constraint for the target,
// dropping non-matching platform keys and merging matching ones.
// ReduceDeps flattens a recipe dependency map to project → constraint for the
// target, as the RECIPE spells the constraint.
//
// Exported because a caller that needs the constraint must not derive it from
// DepSpecs. That renders a pkgx WIRE form — `gnu.org/m4@1`, `cmake.org^3` —
// and trimming the project off it yields "@1", a string nothing can resolve.
// One caller already did that and dropped an artifact it had just built.
//
// So there is one reduction, and everything that asks a question about a
// dependency asks it the same way.
func ReduceDeps(deps map[string]any, tgt target.Target) map[string]string {
	return reduceDepMap(deps, tgt)
}

func reduceDepMap(deps map[string]any, tgt target.Target) map[string]string {
	flat := map[string]string{}
	for k, v := range deps {
		os, arch, isKey := platformKey(k)
		if !isKey {
			flat[k] = valStr(v)
			continue
		}
		if os != "" && os != tgt.Platform {
			continue
		}
		if arch != "" && arch != tgt.Arch {
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			for sk, sv := range sub {
				flat[sk] = valStr(sv)
			}
		}
	}
	return flat
}

// DepSpecs reduces a recipe dependency map into pkgx pkgspecs
// ("project@constraint") for the target, sorted for determinism.
func DepSpecs(deps map[string]any, tgt target.Target) []string {
	flat := reduceDepMap(deps, tgt)
	specs := make([]string, 0, len(flat))
	for p, c := range flat {
		specs = append(specs, depSpec(p, c))
	}
	sort.Strings(specs)
	return specs
}

// depSpec renders a single project+constraint pair as a pkgx pkgspec. pkgx
// (v2.10.3) parses the operator forms differently: a range operator (^ ~ > <)
// is appended DIRECTLY to the project (`cmake.org^3`, `gnu.org/gmp>=6`); an
// exact `=X.Y.Z` and a bare numeric constraint use `@` (`foo@1.2.3`, `foo@3`);
// `*`/empty is a bare project. Appending `@` to a range operator
// (`cmake.org@^3`) makes pkgx reject it with "invalid semver".
func depSpec(project, constraint string) string {
	switch {
	case constraint == "" || constraint == "*":
		return project
	case strings.HasPrefix(constraint, "^"), strings.HasPrefix(constraint, "~"),
		strings.HasPrefix(constraint, ">"), strings.HasPrefix(constraint, "<"):
		return project + constraint
	case strings.HasPrefix(constraint, "="):
		return project + "@" + strings.TrimPrefix(constraint, "=")
	default:
		return project + "@" + constraint
	}
}

// SpecProject extracts the bare project name from a rendered pkgspec, stopping
// at the first version delimiter (@ or a range operator) so dedup keys match
// regardless of the constraint form. depSpec renders a caret/tilde/range
// constraint with NO separator (`invisible-island.net/ncurses^6`), so a
// consumer that splits on "@" alone keeps the operator inside the project name
// — which is how a constrained dependency silently drops out of a closure.
func SpecProject(spec string) string {
	if i := strings.IndexAny(spec, "@^~<>="); i >= 0 {
		return spec[:i]
	}
	return spec
}

// DepTokens resolves each recipe dependency (runtime + build) to a version and
// install prefix ($ZPKG_DIR/<project>/v<version>) and returns the
// `{{deps.<project>.prefix}}` / `{{deps.<project>.version.*}}` moustache tokens.
// resolve maps a project + constraint to a concrete version.
// DepTokens also returns the RESOLVED dependencies it built those tokens from.
//
// ⛔ IT USED TO THROW THEM AWAY. This list — project, version, prefix, for the
// whole build and runtime closure, sorted — IS the build environment: the
// compiler, its libc, every tool the recipe invoked, at the versions actually
// used. It was computed on every build and discarded, which is why a published
// artifact could not say what compiled it.
//
// Resolving a second time elsewhere would be the obvious alternative and the
// wrong one: `resolve` reaches the registry, and two resolutions a moment
// apart are two ANSWERS — measured on this fleet, the same pantry commit gave
// tcl 9.0.4 and 9.1.0 four hours apart.
func DepTokens(runtime, buildDeps map[string]any, tgt target.Target, zpkgDir string, resolve func(project, constraint string) (string, error)) ([]moustache.Token, []moustache.Dep, error) {
	flat := reduceDepMap(runtime, tgt)
	for p, c := range reduceDepMap(buildDeps, tgt) {
		flat[p] = c
	}
	projects := make([]string, 0, len(flat))
	for p := range flat {
		projects = append(projects, p)
	}
	sort.Strings(projects)

	deps := make([]moustache.Dep, 0, len(projects))
	for _, p := range projects {
		ver, err := resolve(p, flat[p])
		if err != nil {
			return nil, nil, err
		}
		deps = append(deps, moustache.Dep{
			Project: p,
			Version: ver,
			// ⛔⛔ ASKED, NOT COMPOSED. `<dir>/<project>/v<version>` is no
			// longer a path that exists once a build is installed under its
			// identity, and this line composed it. Two things rode on the
			// mistake, and both are silent:
			//
			//   - the SCRIPT gets this as {{deps.X.prefix}}, so a build
			//     would be pointed at a directory that is not there;
			//   - the IDENTITY reads the dependency's own hash out of this
			//     path, so every edge contributed an empty hash and the
			//     Merkle property was inert — two builds differing only in
			//     how a dependency was built would have hashed alike.
			//
			// artifact.StorePrefix resolves the installed build and falls back
			// to the composed path when nothing is installed, which is the
			// string this produced before and keeps a dry run unchanged.
			Path: artifact.StorePrefix(zpkgDir, p, artifact.Ver{Raw: ver}),
		})
	}
	return moustache.Deps(deps), deps, nil
}

func platformKey(k string) (os, arch string, ok bool) {
	if m := osArchDepRE.FindStringSubmatch(k); m != nil {
		return m[1], m[2], true
	}
	if platforms[k] {
		return k, "", true
	}
	if arches[k] {
		return "", k, true
	}
	return "", "", false
}

func valStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "*"
	case string:
		return x
	case bool:
		if x {
			return "*"
		}
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

// ToolchainPerl is the perl constraint the base toolchain pins, and the one
// every XS-bearing tool in it must be built against. Stated once because the
// only way it can be wrong is by disagreeing with itself.
const ToolchainPerl = "~5.44"

// ToolchainGawk is the gawk constraint the base toolchain pins. Stated once,
// for the same reason as ToolchainPerl: the spelling is the whole content, and
// a copy of it in a test is a copy that cannot disagree.
const ToolchainGawk = "~5.3"

// perlXSToolchainProjects are the base-toolchain members that ship compiled
// perl modules, so the perl they resolve to is not a preference but a hard
// requirement. CheckToolchainPerl reads what each one actually declares.
var perlXSToolchainProjects = []string{"gnu.org/texinfo", "gnu.org/help2man"}

// CheckToolchainPerl reports every XS-bearing toolchain recipe whose own
// `perl.org` constraint disagrees with ToolchainPerl.
//
// It reads the recipes rather than a copy of them. That distinction is the
// whole point: the unit test that claimed to check this asserted the pin
// equalled the string "~5.42", which was texinfo's constraint on the day it was
// written. texinfo moved to ~5.44, the literal did not, and the test kept
// passing while every man-page-generating build broke.
//
// A recipe that is absent is not a disagreement — a pantry need not be
// complete, and refusing to build because a file is missing would be a worse
// failure than the one this prevents.
func CheckToolchainPerl(set *logical.Set, pantryDir string) []error {
	var problems []error
	for _, proj := range perlXSToolchainProjects {
		r, err := recipefile.LoadOverridden(set, pantryDir, proj)
		switch {
		case errors.Is(err, recipefile.ErrNoRecipe):
			// Absent is not a disagreement: a pantry need not be complete.
			continue
		case err != nil:
			// A recipe that EXISTS and does not parse is one, and saying so is
			// the whole job of this check.
			problems = append(problems, fmt.Errorf("%s: %w", proj, err))
			continue
		}
		got, ok := r.Dependencies["perl.org"]
		if !ok {
			continue
		}
		if s := strings.TrimSpace(fmt.Sprint(got)); s != ToolchainPerl {
			problems = append(problems, fmt.Errorf(
				"%s declares perl.org %s but the base toolchain pins %s: an XS module built against one refuses to load under the other",
				proj, s, ToolchainPerl))
		}
	}
	return problems
}

// BaseToolchain is the ambient build toolset brewkit provides so recipes need
// only declare their SPECIFIC deps. Without it, autotools packages fail on
// aclocal/makeinfo not-found (proven with wget).
func BaseToolchain() []string {
	return []string{
		"gnu.org/autoconf", "gnu.org/automake", "gnu.org/libtool", "gnu.org/m4",
		"gnu.org/make", "gnu.org/gettext", "gnu.org/texinfo",
		// help2man for the same reason texinfo is here: autotools recipes generate
		// their man pages with it through build-aux/missing, and it must be in the
		// EVAL -- not merely on PATH -- because pkgx only exports a package's
		// runtime env (help2man publishes PERL5LIB for the Locale::gettext it
		// bundles) for packages in the closure. gnu.org/libidn2 died without it.
		"gnu.org/help2man",
		// Pin perl to the line the XS-bearing tools in this toolchain are BUILT
		// against. texinfo, help2man and gettext all ship compiled perl modules,
		// and an XS module refuses to load under any other API version — in both
		// directions:
		//
		//   Perl API version v5.42.0 of …/TreeElementXS.c does not match v5.44.0
		//   Perl API version v5.44.0 of …/gettext.c        does not match v5.42.0
		//
		// The second is what this pin caused. It said ~5.42 while all three
		// recipes had moved to ~5.44, so every autotools recipe that generates a
		// man page through build-aux/missing died in help2man — gnu.org/libidn2
		// and gnu.org/fribidi both failed their rebuild on it.
		//
		// A recipe that needs another perl still overrides this (see EvalDeps).
		// CheckToolchainPerl is what notices when they part company again: the
		// test that was supposed to guarantee this compared the pin against a
		// LITERAL copied out of texinfo, so when texinfo moved the copy did not,
		// and the check went on passing.
		"perl.org" + ToolchainPerl,
		"gnu.org/sed", "gnu.org/coreutils", "gnu.org/grep",
		// Pin gawk to 5.3. gawk 5.4.1 mishandles the option-resolution scripts
		// autotools packages use to generate config headers, and "drops
		// PNG_SETJMP_SUPPORTED" undersells it. Same libpng 1.6.58 tree, same
		// ./configure, only AWK= differs:
		//
		//   gawk 5.3.2   202 #define    11 /*#undef
		//   gawk 5.4.1    27 #define   186 /*#undef
		//
		// 175 features off, 0 on in the other direction. Every NUMERIC setting
		// survives (PNG_ZBUF_SIZE, PNG_USER_WIDTH_MAX…) and every BOOLEAN goes to
		// /*#undef*/, so the option evaluation is collapsing rather than losing an
		// entry. PNG_SETJMP_SUPPORTED is merely the first one the compiler names;
		// the errors that follow are about png_read_info, because PNG_READ_SUPPORTED
		// went too. A libpng that BUILT under this gawk would be a libpng with no
		// features — failing to compile is the lucky outcome.
		//
		// Probably the same bug as gawk's unreleased 5.4.2 NEWS entry, "Gawk should
		// now once again work correctly when compiled without the GMP and MPFR
		// libraries": our gawk is built without either. But ftp.gnu.org stops at
		// 5.4.1 and gawk-5.4.2.tar.gz is a 404, so there is nothing to relax TO —
		// the fix is in git and in no release. Check for a release before assuming
		// a later 5.4.x will do.
		//
		// Spelt with "~", not "@5.3". A BARE version is a caret in this resolver —
		// `artifact`'s satisfies ends "default: // \"^\" and bare … sameN(v, base, 1)"
		// — so `gawk@5.3` means ">=5.3, same major" and ADMITS 5.4.1, the one
		// version this line exists to exclude. Measured against the registry, one
		// empty store each:
		//
		//	gawk@5.3   -> 5.4.1      gawk~5.3    -> 5.3.2
		//	gawk^5.3   -> 5.4.1      gawk<5.4    -> 5.3.2
		//	gawk@5.3.2 -> 5.4.1      gawk@=5.3.2 -> 5.3.2
		//
		// It read as a pin for as long as it existed because no 5.3.x was published
		// for darwin: vacuous and misspelt are indistinguishable until the version
		// you meant to select exists.
		"gnu.org/gawk" + ToolchainGawk,
		// bison provides the yacc/bison grammar compiler. autotools packages that
		// ship a .y grammar (e.g. gettext's gettext-runtime/intl/plural.y) regenerate
		// the .c from it during the build via ylwrap; without bison that step fails
		// with "bison: command not found" (Error 127). Provides bin/bison + bin/yacc.
		"gnu.org/bison",
		"freedesktop.org/pkg-config",
	}
}

// EvalDeps is the full `pkgx +…` set for a build: the recipe's own runtime +
// build deps, then the base toolchain filling whatever they did not ask for,
// de-duplicated by project and sorted.
//
// The ORDER is the point. The base toolchain is a floor — "these tools must be
// present" — not a pin, so a recipe that constrains one of those projects must
// win. It used to lose: the base was added first and the dedup dropped the
// recipe's spec, so gnu.org/texinfo, which declares `perl.org: ~5.42` because
// its XS modules are compiled against that perl, silently got the base's
// unconstrained perl.org — 5.44 — and every recipe that runs makeinfo died with
//
//	Perl API version v5.42.0 of …/TreeElementXS.c does not match v5.44.0
//
// The same silent override applied to every base project (gawk, make, bison…),
// so a recipe could never correct one.
// EvalLinkDeps is the set a build LINKS against: the recipe's own runtime
// dependencies, and nothing else.
//
// These are the constraints that have to agree with what a CONSUMER will
// resolve, because they are the ones that end up as @rpath references in the
// artefact. Nothing a build merely runs belongs here.
func EvalLinkDeps(runtime map[string]any, tgt target.Target) []string {
	return sortedSpecs(DepSpecs(runtime, tgt))
}

// EvalToolDeps is the set a build RUNS: the recipe's build dependencies plus
// the base toolchain. Nothing here is linked into the artefact, so its version
// constraints are nobody else's business.
//
// Keeping these apart from the link set is what lets qt.io build at all. qt
// declares unicode.org ^71 as a LINK dependency and nodejs.org as a BUILD one,
// and nodejs needs unicode.org ^73 to start. ICU bumps its major — and its
// soname — every release, so the two can never intersect:
//
//	pkgx: no version of unicode.org satisfies "^71" AND "^73" (available: 3);
//	      asked for by ^71 (requested), ^73 (nodejs.org)
//
// They did not need to. nodejs runs as a build step and exits; its ICU is never
// in the same process as qt's. One closure asked a question that has no answer.
//
// The project itself is filtered out of the base toolchain for the reason
// EvalDeps gives below: its own published artifact must not shadow the thing
// being built.
func EvalToolDeps(project string, runtime, buildDeps map[string]any, tgt target.Target) []string {
	out := DepSpecs(buildDeps, tgt)
	// A recipe that names a toolchain project REPLACES the toolchain's pin, and
	// it does so from either list. Splitting the closures must not turn that
	// override into a coexistence: two perls in one build is the XS mismatch the
	// ToolchainPerl pin exists to prevent —
	//
	//	Perl API version v5.42.0 of …/TreeElementXS.c does not match v5.44.0
	//
	// — and the recipe's copy being first on PATH would not stop the toolchain's
	// modules finding the other one.
	named := map[string]bool{project: true}
	for _, s := range DepSpecs(runtime, tgt) {
		named[SpecProject(s)] = true
	}
	for _, s := range out {
		named[SpecProject(s)] = true
	}
	for _, s := range BaseToolchain() {
		if named[SpecProject(s)] {
			continue
		}
		out = append(out, s)
	}
	return sortedSpecs(out)
}

// sortedSpecs orders a spec list so the generated script is deterministic.
//
// No de-duplication: after the split each list is unique by construction.
// DepSpecs already reduces a platform override to one entry per project
// (`unicode.org: ^71` with `linux: {unicode.org: ~71}` yields `unicode.org~71`
// alone), and EvalToolDeps drops any toolchain entry the recipe names. EvalDeps
// needed a dedup because it merged three lists into one; these do not, and a
// guard that cannot fire is worse than none — it reads as a guarantee.
func sortedSpecs(specs []string) []string {
	out := append([]string(nil), specs...)
	sort.Strings(out)
	return out
}

// BootstrapToolDeps is EvalToolDeps WITHOUT the base toolchain: only what the
// recipe itself declares as a build dependency.
//
// It exists because the base toolchain is a CYCLE with no entry point, and
// that is invisible until an architecture has no artifacts at all. Every build
// gets the fifteen projects BaseToolchain names injected into its pkgx
// environment, as ARTIFACTS -- so on linux/s390x, where neither this registry
// nor dist.pkgx.dev publishes anything, gnu.org/m4 fails on
//
//	pkgx: no version of freedesktop.org/pkg-config satisfies  AND is
//	      published for linux/s390x
//
// although m4's recipe declares no build dependencies at all. Building
// pkg-config asks for the other fourteen in turn. Nothing can be first.
//
// --libc=pkgx does not help and neither does its absence: the build container's
// distribution supplies a COMPILER fallback, never a declared dependency, so
// both modes go through pkgx and both demand an artifact.
//
// So one generation has to be made with the host's own tools, into a registry
// that generation never leaves. This is that escape, and it is deliberately
// the smallest one that works: the recipe's own build dependencies still
// resolve as artifacts, and the LINK closure is untouched, because what a
// artifact links against is what it ships -- only the tools that RUN the build
// come from outside.
func BootstrapToolDeps(buildDeps map[string]any, tgt target.Target) []string {
	return sortedSpecs(DepSpecs(buildDeps, tgt))
}

// WithoutSelfDep removes a recipe's build dependency on ITSELF.
//
// Four recipes in the bootstrap set declare one: gnu.org/gcc, gnu.org/sed,
// gnu.org/grep and rust-lang.org/cargo. It is the right declaration almost
// always -- gcc's own comment says ">=14 lets the newest gcc WE have build the
// older one, so the seed comes from our own chain instead of an upstream
// binary" -- and it is exactly wrong when the chain does not exist yet. On an
// architecture with no artifacts, a project that needs itself can never be
// first, and nothing downstream of it can either: gnu.org/glibc build-depends
// on gcc 14, so the whole toolchain sits behind that one edge.
//
// Only in bootstrap mode, and only the self-edge. Every other build dependency
// stays an artifact, because every other one CAN be built in order.
func WithoutSelfDep(project string, buildDeps map[string]any) map[string]any {
	if _, ok := buildDeps[project]; !ok {
		return buildDeps
	}
	out := make(map[string]any, len(buildDeps))
	for k, v := range buildDeps {
		if k == project {
			continue
		}
		out[k] = v
	}
	return out
}

// HostPrefixForSelfDep gives {{deps.<project>.prefix}} a value when bootstrap
// dropped a recipe's dependency on ITSELF and the machine demonstrably
// provides what the recipe says it provides.
//
// gnu.org/sed build-depends on gnu.org/sed for one line:
//
//	export PATH="{{deps.gnu.org/sed.prefix}}/bin:$PATH"
//
// — putting a known-good sed in front of whatever the system has. On an
// architecture with no sed artifact the system's IS the only sed, and the
// unresolved token stopped the build with the guard Runner.Build added for
// exactly this shape.
//
// The prefix is not invented. The recipe says it provides `bin/sed`, the host
// says `sed` is at /usr/bin/sed, and the prefix that makes both true is /usr.
// Where the two do not agree — the binary is somewhere that is not
// <prefix>/bin, or the host does not have it at all — no token is produced and
// the build still refuses. A guessed path would send a compiler somewhere
// nobody chose.
//
// The SELF dependency only, and that restriction is the whole of its
// justification. `provides:` belongs to the recipe being built; it says what
// THIS project puts on the machine and nothing about any other. A first
// version took a list of every dropped dependency and read this recipe's
// provides for each of them, which would have answered "cmake.org's prefix is
// /usr" because the recipe in hand ships a bin/ of its own. A dropped
// dependency that is not the self-edge still leaves its token unresolved, and
// the build still refuses — loudly, which is the correct outcome for a
// question this cannot answer.
func HostPrefixForSelfDep(project string, provides any, look func(string) (string, error)) []moustache.Token {
	if look == nil {
		return nil
	}
	for _, rel := range providedBins(provides) {
		path, err := look(filepath.Base(rel))
		if err != nil {
			continue
		}
		// <prefix>/bin/<name>, and nothing else counts.
		if dir := filepath.Dir(path); filepath.Base(dir) == "bin" {
			return []moustache.Token{{From: "deps." + project + ".prefix", To: filepath.Dir(dir)}}
		}
	}
	return nil
}

// providedBins reads a recipe's `provides:` as a list of relative paths.
func providedBins(provides any) []string {
	list, ok := provides.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range list {
		if s, ok := v.(string); ok && strings.HasPrefix(s, "bin/") {
			out = append(out, s)
		}
	}
	return out
}

// ProvidedCommands is the COMMAND names a recipe puts on PATH for a target,
// without their `bin/` prefix, sorted and deduplicated.
//
// `provides:` comes in two shapes, and a reader that knows one of them
// reports nothing for the other instead of failing:
//
//	provides:            provides:
//	  - bin/jq             linux:  [bin/podman, bin/podman-remote]
//	                       darwin: [bin/podman, bin/podman-mac-helper]
//
// providedBins above handles only the flat list, which is right for what it
// does — it looks for a self-dependency's binary on the HOST, where the
// platform is already decided. A catalogue is built FOR a platform, and
// podman on linux provides a different set from podman on darwin, so this
// takes the same reduction the dependency map gets.
//
// `bin/` only. A recipe that provides `lib/libfoo.so` provides nothing
// anybody types.
func ProvidedCommands(provides any, tgt target.Target) []string {
	seen := map[string]bool{}
	add := func(v any) {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(s, "bin/") {
			return
		}
		if n := strings.TrimPrefix(s, "bin/"); n != "" {
			seen[n] = true
		}
	}
	switch p := provides.(type) {
	case []any:
		for _, v := range p {
			add(v)
		}
	case map[string]any:
		for k, v := range p {
			os, arch, isKey := platformKey(k)
			if !isKey || (os != "" && os != tgt.Platform) || (arch != "" && arch != tgt.Arch) {
				continue
			}
			if list, ok := v.([]any); ok {
				for _, e := range list {
					add(e)
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// WithoutUnresolvable drops the build dependencies this registry cannot
// provide for the target, asking `resolve` about each one.
//
// Only in bootstrap mode, and the reason it is safe is written a few functions
// above: EvalToolDeps is "the set a build RUNS", and "Nothing here is linked
// into the artefact." A build dependency is a TOOL. The link closure --
// EvalLinkDeps, what the artifact actually carries -- is untouched.
//
// It is what the remaining s390x seed failures all were, each differently:
//
//   - curl.se/ca-certs declares curl.se so its script can run
//     `curl -k https://curl.se/ca/… -o cert.pem`. curl.se in turn needs
//     ca-certs, so neither can be first. The host has a curl.
//   - perl.org declares `llvm.org: <19` on linux: a compiler, named by artifact.
//     The host has a compiler; that is the whole premise of --bootstrap.
//
// `resolve` is asked whether the tool can be INSTALLED, not merely whether a
// version of it exists. The two differ, and the difference stopped the seed:
// github.com/besser82/libxcrypt build-depends on perl.org, perl.org WAS in the
// seed registry, and the build still died —
//
//	zpkb: the tool environment failed: zpkgx +freedesktop.org/pkg-config~0.29 +perl.org
//	zpkgx: GET …/github.com/besser82/libxcrypt/linux/s390x/versions.txt: Not Found
//
// because perl's closure needs github.com/besser82/libxcrypt — the project
// being built. OUR OVERLAY declares that edge for linux (upstream's perl.org
// does not), so it is an ordinary recipe dependency and no soname map is
// involved; an earlier version of this comment said otherwise. A tool you
// cannot install is not a tool you have, so the question has to be about the
// closure.
//
// A drop is reported, not silent: a seed artifact built without a tool somebody
// declared is a fact that outlives the run.
//
// If the recipe needed that dependency's PATH rather than its binaries, the
// build refuses instead — see the unresolved-{{deps.…}} check in Runner.Build.
// That guard is why this can be a blunt rule without being a reckless one.
func WithoutUnresolvable(buildDeps map[string]any, tgt target.Target,
	resolve func(project, constraint string) (string, error), log func(string)) (map[string]any, []string) {
	if resolve == nil || len(buildDeps) == 0 {
		return buildDeps, nil
	}
	var dropped []string
	// reduceDepMap, exactly as DepTokens does it, and NOT DepSpecs.
	//
	// DepSpecs renders a pkgx WIRE FORM -- `gnu.org/m4@1`, `cmake.org^3` -- and
	// the first version of this took the constraint by trimming the project off
	// that, which yields "@1". resolve was then asked a question nobody can
	// answer, said no, and the dependency was dropped as unavailable:
	//
	//	bootstrap: no gnu.org/m4 here — taking it from the host
	//	           (no version of gnu.org/m4 satisfies "@1" (available: 1))
	//
	// "available: 1" is the tell — the artifact WAS there, freshly built, and
	// 1.4.21 satisfies "1". The judge has to ask what the subject asks.
	keep := map[string]any{}
	for proj, cons := range reduceDepMap(buildDeps, tgt) {
		if _, err := resolve(proj, cons); err != nil {
			// "cannot install", not "no X here": perl.org WAS in the seed
			// registry and still could not be installed, and a message that
			// said it was absent would send a reader looking for the wrong
			// thing. The error in the parentheses says which it is.
			if log != nil {
				log(fmt.Sprintf("bootstrap: cannot install %s here — taking it from the host (%v)", proj, err))
			}
			dropped = append(dropped, proj)
			continue
		}
		keep[proj] = cons
	}
	sort.Strings(dropped)
	return keep, dropped
}

// Deprecated: the build now composes two closures — EvalLinkDeps and
// EvalToolDeps. This is kept as the CONTROL for that split: a test asserts that
// it still puts a link constraint and a build tool in ONE list, which is what
// forced qt.io's unicode.org ^71 and nodejs.org's ^73 through a single
// intersection. Delete it once that history stops being worth pinning.
func EvalDeps(project string, runtime, buildDeps map[string]any, tgt target.Target) []string {
	seen := map[string]bool{}
	var out []string
	add := func(specs []string) {
		for _, s := range specs {
			key := SpecProject(s)
			if !seen[key] {
				seen[key] = true
				out = append(out, s)
			}
		}
	}
	add(DepSpecs(runtime, tgt))
	add(DepSpecs(buildDeps, tgt))
	// A package's OWN published artifact never joins the toolchain of its own
	// build. It would shadow the thing being built with an older copy — and if
	// that copy is broken, the package can no longer be repaired at all:
	//
	//   configure: error: no working 'grep' found
	//     A working 'grep' command is needed to build GNU Grep.
	//
	// which is where gnu.org/grep sat on 2026-09-05, its published artifact
	// unable to start because a dependency's MINOR upgrade had moved out from
	// under an absolute install name. Nothing else in the factory could make
	// the next grep, and the tools that need grep (curl's configure, autoconf's
	// grep-based type probes) failed in ways that named neither grep nor the
	// real cause.
	//
	// Only the BASE toolchain is filtered: a recipe that deliberately names
	// itself is stating something we have no business overruling.
	base := BaseToolchain()
	kept := base[:0:0]
	for _, s := range base {
		if SpecProject(s) == project {
			continue
		}
		kept = append(kept, s)
	}
	add(kept)
	sort.Strings(out)
	return out
}

// SanitizedEnv is the clean environment the build script runs within (brewkit's
// clearEnv): a fixed PATH, ZPKG_DIR and HOME, plus a small allow-list passed
// through from the caller's environment. It prevents a stray toolchain (eg. a
// system Homebrew) from leaking into the build (proven: wget linked the wrong
// openssl under an unsanitized env).
func SanitizedEnv(home, zpkgDir string) []string {
	env := []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + home,
		"ZPKG_DIR=" + zpkgDir,
		// Neutralise autotools maintainer-mode. A release tarball ships a correct
		// configure/Makefile.in/aclocal.m4, but timestamp skew after extraction
		// makes `make` try to regenerate them with a pinned aclocal-1.NN /
		// automake-1.NN that isn't installed (→ "aclocal-1.18: command not
		// found", exit 127). Passing these as make variable overrides via
		// MAKEFLAGS no-ops every regen rule, so the shipped generated files are
		// used as-is. (make-only; a recipe's own direct autoreconf is untouched.)
		//
		// MAKEINFO is deliberately NOT no-op'd: unlike the AUTO* tools it does not
		// regenerate the build system — it produces .info manuals that some
		// recipes then INSTALL (glibc's manual/subdir_install installs libc.info).
		// Forcing MAKEINFO=true made that step emit nothing, so the subsequent
		// `install libc.info*` failed. The real makeinfo ships in the base
		// toolchain (gnu.org/texinfo), so let it run.
		"MAKEFLAGS=ACLOCAL=true AUTOMAKE=true AUTOCONF=true AUTOHEADER=true AUTOPOINT=true",
		// Builds run as root in the CI container; autotools' "you should not run
		// configure as root" check would abort otherwise. Bypassing it is the
		// standard build-sandbox posture (Homebrew/distros do the same).
		"FORCE_UNSAFE_CONFIGURE=1",
	}
	// LD_LIBRARY_PATH is passed through when the caller set one. Normally it is
	// absent and must stay so — a host's library path is exactly the kind of
	// leakage the sanitised env exists to stop. But in a FROM-scratch builder
	// there is no system libc at all: every tool, `mkdir` included, finds its
	// libc.so.6 through that variable, and dropping it makes the very first
	// command of a build fail with
	//   mkdir: error while loading shared libraries: libc.so.6: cannot open …
	// The caller opting in (an ENV in the builder image) is a deliberate choice,
	// not ambient host state.
	// ZPKG_DIST / ZPKG_PANTRY / ZPKG_PANTRY_OVERLAY choose WHERE the `pkgx +deps`
	// line of the generated script resolves from. Dropping them silently sent
	// every build back to the default ghcr.io registry and the upstream pantry —
	// a local registry cache was bypassed by the builds it exists for, and a
	// corrected overlay recipe was never seen (curl.se then asked for the
	// unsatisfiable `openssl.org: ^1.1` of the upstream recipe and the whole
	// dependency environment died). These name a distribution point, not host
	// toolchain state, so passing them through does not reopen the leak
	// SanitizedEnv guards against.
	//
	// ZPKG_VERIFY travels with them, and for the same reason: it is the other
	// half of the same decision — which registry, and on what terms. Verification
	// is on by default and a build inherits that; the opt-out exists for a test
	// harness pointed at a scratch registry of deliberately unsigned artifacts,
	// where the alternative is not "less safety" but "no test".
	// ZPKG_CACHE belongs with ZPKG_DIST for exactly the reason spelled out above:
	// it names a distribution point. Dropping it sent the `pkgx +deps` line of
	// every generated script past the pull-through cache the job had just been
	// configured to use.
	//
	// QEMU_RESERVED_VA is passed through because a cross-arch build may be
	// running under qemu-user, and our gnu.org/bash is built with bash's own
	// sbrk-based malloc. Under qemu's default reserved address space it cannot
	// allocate at all:
	//   /bin/sh: xmalloc: setlinebuf.c:51: cannot allocate 2016 bytes (0 bytes allocated)
	// on the FIRST command of the build, which then looks like a broken recipe —
	// a make target failing, an `ln` linking a file to itself from an empty
	// variable. Measured in an emulated container: our bash fails, the same bash
	// with QEMU_RESERVED_VA set succeeds, and the distribution's bash (built
	// --without-bash-malloc) never had the problem.
	// GITHUB_TOKEN is NOT in this list, and used to be.
	//
	// A build script is third-party code: the recipes come from
	// pkgxdev/pantry, they run as root in the sovereign chroot, and the
	// workflow's token carries `packages: write` on the whole organisation.
	// Handing it to them means any recipe can publish an artifact.
	//
	// It was passed through "for recipes that fetch from GitHub". Measured
	// against a fresh pantry on 2026-10-05, that is not what uses it:
	//
	//	1899 recipes · 2 reference GITHUB_TOKEN · BOTH in their `test:` block
	//	0 in go-zpkg/pantry-overlay
	//	bk's own fetcher never sends it — fetch/ has no Authorization header
	//
	// So no build block in the pantry wants it, and the rate-limit argument
	// does not apply to bk's downloads either. The two that do want it are
	// tests, and `bk test` adds it there on purpose — see cmd/bk/test.go.
	// Privilege where the need was measured, and not one caller wider.
	for _, k := range []string{"LANG", "LOGNAME", "USER", "TERM", "ZPKG_PANTRY_DIR", "ZPKG_PANTRY_PATH",
		"ZPKG_DIST", "ZPKG_CACHE", "ZPKG_PANTRY", "ZPKG_PANTRY_OVERLAY", "ZPKG_VERIFY",
		"LD_LIBRARY_PATH", "QEMU_RESERVED_VA"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// autotools file tiers, oldest → newest, so outputs end up newer than inputs.
var autotoolsTiers = [][]string{
	// Inputs (oldest): configure.ac/.am plus EVERY *.m4 macro — including those
	// under m4/ that ship in a release tarball at a recent mtime. Without ageing
	// them, aclocal.m4 (next tier) can be older than an m4 macro, so make tries
	// to regenerate it with a pinned `aclocal-1.NN` that isn't installed.
	{".ac", ".am", ".m4"},
	// aclocal.m4 is bumped one tier newer than the .m4 macros above (the last
	// matching tier wins), so it never looks stale against them.
	{"aclocal.m4"},
	// The GENERATED configure script, by every name a release tarball gives
	// it. `configure.sh` is rsync's, and leaving it out did the exact opposite
	// of this function's job: the tiers above rejuvenate aclocal.m4 to an hour
	// ago while the untouched script keeps its tarball mtime, so on
	// rsync-3.5.1 the generated file came out SEVEN DAYS older than its own
	// prerequisite —
	//
	//	configure.ac   2026-09-28 06:56:48
	//	aclocal.m4     2026-09-28 06:57:48
	//	configure.sh   2026-09-21 05:55:19
	//
	// — make regenerated it with whatever autoconf was in the environment, and
	// rsync's own Makefile stopped the build dead:
	//
	//	configure.sh has CHANGED.
	//	You may need to run: make reconfigure
	//	make: *** [Makefile:280: configure.sh] Error 1
	//
	// `preconfigure` is glibc's, and it was added here after the s390x seed
	// died on a message about a machine glibc has supported for decades:
	//
	//	configure: error: The s390x is not supported.
	//
	// glibc 2.44 grew a sysdeps/s390/preconfigure.ac — 2.42 had ten of those
	// and 2.44 has eleven — so the rule
	//
	//	%/preconfigure: %/preconfigure.ac aclocal.m4; $(autoconf-it)
	//
	// could finally fire for s390. In the tarball, aclocal.m4 and
	// sysdeps/s390/preconfigure carry ONE mtime (Jul 24 15:16 for 2.44); the
	// tier above rejuvenates aclocal.m4 and nothing rejuvenated the
	// preconfigure, so the prerequisite became an hour newer than its target.
	// make then ran `$(AUTOCONF) … > $@.new; mv -f $@.new $@` with the
	// AUTOCONF=true that bk itself exports, writing an EMPTY file over the four
	// lines that turn $machine from `s390x` into `s390/s390-64`.
	//
	// The failure is a whole configure LATER: the recipe's own configure
	// succeeds and lists sysdeps/s390 quite happily, and it is the re-run make
	// triggers through Makeconfig:103 that sources the emptied fragment.
	//
	// Exact names, never a `configure*` prefix: the tiers are applied in order
	// and the last match wins, so a prefix would drag configure.ac out of the
	// inputs tier and into this one. `preconfigure.ac` is unaffected for the
	// same reason — it matches the `.ac` suffix in the inputs tier, and an
	// exact name cannot claim it.
	{"config.h.in", "configure", "configure.sh", "preconfigure"},
	{"Makefile.in"}, // final outputs
}

// TouchAutotools defeats autotools maintainer-mode: an extracted tarball's file
// timestamps make `make` think configure.ac changed and rerun aclocal/automake
// (which fail without the exact tool versions). Touching the generated files
// newer than their sources, in ascending tiers, marks the build system fresh.
func TouchAutotools(srcDir string) error {
	base := time.Now().Add(-time.Hour)
	for tier, pats := range autotoolsTiers {
		when := base.Add(time.Duration(tier) * time.Minute)
		err := filepath.WalkDir(srcDir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			name := d.Name()
			for _, pat := range pats {
				if name == pat || (strings.HasPrefix(pat, ".") && strings.HasSuffix(name, pat)) {
					return osChtimes(p, when, when)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
