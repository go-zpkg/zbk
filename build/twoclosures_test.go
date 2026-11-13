package build

import (
	"errors"
	"strings"
	"testing"
)

// The link set is what the artefact is built against, and nothing else: no
// build dependency and no base toolchain reaches it.
func TestEvalLinkDepsIsRuntimeOnly(t *testing.T) {
	got := EvalLinkDeps(map[string]any{"zlib.net": "^1", "unicode.org": "^71"}, lin())
	if len(got) != 2 || !contains(got, "zlib.net^1") || !contains(got, "unicode.org^71") {
		t.Fatalf("link deps = %v", got)
	}
	for _, s := range got {
		if strings.HasPrefix(s, "gnu.org/autoconf") || strings.HasPrefix(s, "nodejs.org") {
			t.Errorf("a tool reached the link set: %q", s)
		}
	}
}

// The tool set is what the build runs: its build dependencies and the base
// toolchain.
func TestEvalToolDepsIsBuildPlusToolchain(t *testing.T) {
	got := EvalToolDeps("acme.org/thing", nil, map[string]any{"nodejs.org": "*"}, lin())
	if !contains(got, "nodejs.org") {
		t.Errorf("build dependency missing: %v", got)
	}
	if !contains(got, "gnu.org/autoconf") {
		t.Errorf("base toolchain missing: %v", got)
	}
}

// qt.io's shape, which one closure could not resolve: it LINKS unicode.org ^71
// and its build RUNS nodejs.org, whose own runtime needs ^73. The two sets must
// not mention each other, so the two resolutions never have to agree.
func TestTheQtShapeSplitsCleanly(t *testing.T) {
	runtime := map[string]any{"unicode.org": "^71", "freetype.org": "*"}
	buildD := map[string]any{"nodejs.org": "*", "python.org": ">=2.7"}

	link := EvalLinkDeps(runtime, lin())
	tools := EvalToolDeps("qt.io", runtime, buildD, lin())

	if !contains(link, "unicode.org^71") {
		t.Fatalf("link set lost qt's own constraint: %v", link)
	}
	if contains(link, "nodejs.org") {
		t.Errorf("the build tool reached the link set: %v", link)
	}
	if !contains(tools, "nodejs.org") {
		t.Errorf("tool set lost nodejs: %v", tools)
	}
	for _, s := range tools {
		if SpecProject(s) == "unicode.org" {
			t.Errorf("qt's link constraint reached the tool set as %q — nodejs would have to agree with it", s)
		}
	}

	// The control: the single-closure form this replaces puts both in one list,
	// which is what forced `^71` and nodejs's `^73` through one intersection.
	one := EvalDeps("qt.io", runtime, buildD, lin())
	if !contains(one, "unicode.org^71") || !contains(one, "nodejs.org") {
		t.Fatalf("control did not reproduce the single closure: %v", one)
	}
}

// Splitting must not turn the toolchain OVERRIDE into a coexistence: a recipe
// that names a toolchain project keeps its own, and the toolchain's copy is
// dropped rather than installed beside it.
func TestARecipesOwnToolchainPinStillReplacesTheBaseOne(t *testing.T) {
	// named in the runtime deps
	tools := EvalToolDeps("acme.org/thing", map[string]any{"perl.org": "^5.99"}, nil, lin())
	if contains(tools, "perl.org"+ToolchainPerl) {
		t.Errorf("the base perl survived a recipe that names its own: %v", tools)
	}
	if link := EvalLinkDeps(map[string]any{"perl.org": "^5.99"}, lin()); !contains(link, "perl.org^5.99") {
		t.Errorf("the recipe's own perl is missing from the link set: %v", link)
	}

	// named in the build deps
	tools = EvalToolDeps("acme.org/thing", nil, map[string]any{"gnu.org/gawk": "^5.4"}, lin())
	if contains(tools, "gnu.org/gawk"+ToolchainGawk) {
		t.Errorf("the base gawk survived a recipe that names its own: %v", tools)
	}
	if !contains(tools, "gnu.org/gawk^5.4") {
		t.Errorf("the recipe's own gawk is missing: %v", tools)
	}

	// and the project itself never joins its own toolchain
	if contains(EvalToolDeps("gnu.org/grep", nil, nil, lin()), "gnu.org/grep") {
		t.Error("a project's own published artifact joined the toolchain of its build")
	}
}

// TestBootstrapToolDepsDropsTheToolchainAndNothingElse.
//
// The base toolchain is what makes a first fill on a new architecture
// impossible: m4 declares no build dependencies and still fails on
// freedesktop.org/pkg-config, because BaseToolchain is injected into every
// build. Bootstrap mode drops exactly that, and must drop nothing else -- the
// recipe's OWN build dependencies are still artifacts, deliberately.
func TestBootstrapToolDepsDropsTheToolchainAndNothingElse(t *testing.T) {
	// The real case: a recipe with no build dependencies of its own.
	if got := BootstrapToolDeps(nil, lin()); len(got) != 0 {
		t.Errorf("a recipe declaring nothing must ask for nothing, got %v", got)
	}
	// The control, same inputs, ordinary mode: the whole toolchain arrives.
	full := EvalToolDeps("gnu.org/m4", nil, nil, lin())
	if !contains(full, "freedesktop.org/pkg-config") {
		t.Fatalf("premise wrong: the toolchain no longer brings pkg-config: %v", full)
	}

	// And what the recipe names for itself survives.
	got := BootstrapToolDeps(map[string]any{"nodejs.org": "*"}, lin())
	if len(got) != 1 || SpecProject(got[0]) != "nodejs.org" {
		t.Errorf("BootstrapToolDeps = %v, want nodejs.org alone", got)
	}
}

// TestBaseToolchainHasNoEntryPoint is the finding itself, asserted rather than
// described: EVERY member of the base toolchain is handed the others, so there
// is no member that can be built first. A future toolchain with an entry point
// would make --bootstrap unnecessary, and this test is how that would be
// noticed rather than assumed.
func TestBaseToolchainHasNoEntryPoint(t *testing.T) {
	for _, spec := range BaseToolchain() {
		proj := SpecProject(spec)
		// Built in the ordinary way, with no recipe-declared deps at all.
		tools := EvalToolDeps(proj, nil, nil, lin())
		var others []string
		for _, s := range tools {
			if SpecProject(s) != proj {
				others = append(others, SpecProject(s))
			}
		}
		if len(others) == 0 {
			t.Errorf("%s needs nothing else: the toolchain HAS an entry point now, "+
				"so --bootstrap may no longer be the only way in", proj)
		}
	}
}

// TestWithoutSelfDepRemovesOnlyTheSelfEdge.
//
// gnu.org/gcc build-depends on gnu.org/gcc, and its comment explains why that
// is right: ">=14 lets the newest gcc WE have build the older one, so the seed
// comes from our own chain instead of an upstream binary." On an architecture
// with no chain yet, the same edge means nothing can be first -- and
// gnu.org/glibc build-depends on gcc 14, so the entire toolchain sits behind
// it.
func TestWithoutSelfDepRemovesOnlyTheSelfEdge(t *testing.T) {
	in := map[string]any{
		"gnu.org/gcc":  ">=14",
		"gnu.org/make": "*",
		"perl.org":     "^5.6.1",
	}
	got := WithoutSelfDep("gnu.org/gcc", in)
	if _, ok := got["gnu.org/gcc"]; ok {
		t.Error("the self edge survived")
	}
	if got["gnu.org/make"] != "*" || got["perl.org"] != "^5.6.1" {
		t.Errorf("the other edges must be untouched, got %v", got)
	}
	// And the input is not mutated: the caller still holds the recipe's map.
	if _, ok := in["gnu.org/gcc"]; !ok {
		t.Error("WithoutSelfDep mutated its argument")
	}
	// A recipe with no self edge is returned as-is rather than copied, which is
	// the common case by far.
	same := map[string]any{"gnu.org/make": "*"}
	if out := WithoutSelfDep("acme.org/thing", same); len(out) != 1 {
		t.Errorf("a recipe without a self edge must come back whole, got %v", out)
	}
}

// TestWithoutUnresolvableKeepsWhatTheRegistryHas.
//
// The last shape of the s390x first fill, and the reason it is safe is a
// sentence already in this file: EvalToolDeps is "the set a build RUNS", and
// "Nothing here is linked into the artefact." A build dependency is a tool.
//
// The two real cases, both two-cycles or compiler pins rather than self edges:
// curl.se/ca-certs declares curl.se so its script can run `curl` to fetch a
// cert bundle, while curl.se needs ca-certs; and perl.org declares
// `llvm.org: <19` on linux, a compiler named by artifact.
func TestWithoutUnresolvableKeepsWhatTheRegistryHas(t *testing.T) {
	in := map[string]any{"curl.se": "*", "gnu.org/make": "*"}
	var logged []string
	resolve := func(p, _ string) (string, error) {
		if p == "curl.se" {
			return "", errors.New("no artifact for linux/s390x")
		}
		return "4.4.1", nil
	}
	got, dropped := WithoutUnresolvable(in, lin(), resolve, func(s string) { logged = append(logged, s) })
	if _, ok := got["curl.se"]; ok {
		t.Error("an unresolvable tool must be left to the host")
	}
	if got["gnu.org/make"] != "*" {
		t.Errorf("a tool the registry HAS must stay an artifact, got %v", got)
	}
	// Reported, not silent: a seed artifact built without a declared tool is a
	// fact that outlives the run.
	if len(logged) != 1 || !strings.Contains(logged[0], "curl.se") {
		t.Errorf("the drop must be named in the log, got %v", logged)
	}
	// And RETURNED, so a failure later can name it. The log line is hundreds
	// of lines back by then, and half the time belongs to another recipe.
	if len(dropped) != 1 || dropped[0] != "curl.se" {
		t.Errorf("dropped = %v, want [curl.se]", dropped)
	}
}

// Without a resolver there is nothing to ask, so nothing may be dropped — a
// test Runner has none, and silently emptying its build deps would make every
// such test agree with anything.
func TestWithoutUnresolvableNeedsAResolver(t *testing.T) {
	in := map[string]any{"curl.se": "*"}
	if got, _ := WithoutUnresolvable(in, lin(), nil, nil); len(got) != 1 {
		t.Errorf("no resolver must mean no change, got %v", got)
	}
	if got, _ := WithoutUnresolvable(nil, lin(), func(string, string) (string, error) { return "", nil }, nil); len(got) != 0 {
		t.Errorf("nothing in, nothing out, got %v", got)
	}
}

// TestWithoutUnresolvableAsksTheConstraintDepTokensAsks.
//
// The defect this pins was found in a build LOG, not in a test: the first
// version derived the constraint from DepSpecs' pkgx wire form and passed
// "@1" where the recipe said "1". resolve cannot answer that, said no, and a
// artifact we had just built was dropped as missing —
//
//	bootstrap: no gnu.org/m4 here — taking it from the host
//	           (no version of gnu.org/m4 satisfies "@1" (available: 1))
//
// "available: 1" is the tell. It was there.
//
// So this asserts the STRING resolve receives, for the three shapes that
// render differently on the wire: a bare number (@1), a range (^3, appended
// with no @) and an exact pin (=1.2.3).
func TestWithoutUnresolvableAsksTheConstraintDepTokensAsks(t *testing.T) {
	in := map[string]any{"gnu.org/m4": "1", "cmake.org": "^3", "acme.org/x": "=1.2.3"}
	got := map[string]string{}
	resolve := func(p, c string) (string, error) { got[p] = c; return "9.9.9", nil }
	_, _ = WithoutUnresolvable(in, lin(), resolve, nil)

	for p, want := range map[string]string{"gnu.org/m4": "1", "cmake.org": "^3", "acme.org/x": "=1.2.3"} {
		if got[p] != want {
			t.Errorf("resolve(%q) got constraint %q, want %q — the recipe's own spelling", p, got[p], want)
		}
	}
	// And the same question DepTokens would ask, from the same input.
	viaTokens := map[string]string{}
	_, _, _ = DepTokens(nil, in, lin(), "/pkgx", func(p, c string) (string, error) { viaTokens[p] = c; return "9.9.9", nil })
	for p := range in {
		if got[p] != viaTokens[p] {
			t.Errorf("%s: this check asks %q, DepTokens asks %q — they must agree", p, got[p], viaTokens[p])
		}
	}
}

// A platform-keyed build dependency must be reduced the same way too: perl.org
// declares llvm.org under `linux:`, and that is where the second real drop of
// the seed run came from.
func TestWithoutUnresolvableReducesPlatformKeys(t *testing.T) {
	in := map[string]any{"linux": map[string]any{"llvm.org": "<19", "gnu.org/make": "*"}}
	resolve := func(p, _ string) (string, error) {
		if p == "llvm.org" {
			return "", errors.New("no artifact here")
		}
		return "4.4.1", nil
	}
	got, _ := WithoutUnresolvable(in, lin(), resolve, nil)
	if _, ok := got["llvm.org"]; ok {
		t.Error("the unresolvable one must go")
	}
	if got["gnu.org/make"] != "*" {
		t.Errorf("the other must survive the reduction, got %v", got)
	}
}

// TestReduceDeps is the one reduction everything asks through.
//
// It is exported because a caller deriving a constraint from DepSpecs gets a
// pkgx WIRE form — `gnu.org/m4@1` — and trimming the project off that yields
// "@1", which nothing can resolve. One caller did exactly that and dropped a
// artifact it had just built.
func TestReduceDeps(t *testing.T) {
	got := ReduceDeps(map[string]any{
		"gnu.org/m4": "1",
		"cmake.org":  "^3",
		"linux":      map[string]any{"llvm.org": "<19"},
		"darwin":     map[string]any{"gnu.org/gettext": "*"},
	}, lin())
	want := map[string]string{"gnu.org/m4": "1", "cmake.org": "^3", "llvm.org": "<19"}
	if len(got) != len(want) {
		t.Fatalf("ReduceDeps = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ReduceDeps[%q] = %q, want %q — the recipe's own spelling", k, got[k], v)
		}
	}
}
