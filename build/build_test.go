package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-zpkg/zpkb/target"
)

func lin() target.Target { return target.Target{Platform: "linux", Arch: "x86-64"} }
func win() target.Target { return target.Target{Platform: "windows", Arch: "x86-64"} }

func TestDepSpecs(t *testing.T) {
	deps := map[string]any{
		"openssl.org":    "^1.1",
		"linux":          map[string]any{"gnu.org/A": "*"},
		"darwin":         map[string]any{"apple.B": "1"},
		"windows/x86-64": map[string]any{"llvm.org/mingw-w64": nil},
		"x86-64":         map[string]any{"arch.only": "2"},
		"aarch64":        map[string]any{"nope": "9"},
	}
	// linux target: openssl + linux sub + x86-64 sub; darwin/windows/aarch64 dropped
	got := DepSpecs(deps, lin())
	want := []string{"arch.only@2", "gnu.org/A", "openssl.org^1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("linux DepSpecs = %v want %v", got, want)
	}
	// windows/x86-64 target: openssl + windows sub (bare) + x86-64 sub
	got = DepSpecs(deps, win())
	want = []string{"arch.only@2", "llvm.org/mingw-w64", "openssl.org^1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("windows DepSpecs = %v want %v", got, want)
	}
	// a platform key whose value isn't a map is ignored
	if g := DepSpecs(map[string]any{"linux": "notamap", "x": "1"}, lin()); !reflect.DeepEqual(g, []string{"x@1"}) {
		t.Errorf("non-map platform = %v", g)
	}
	if len(DepSpecs(nil, lin())) != 0 {
		t.Error("nil deps")
	}
}

// TestDepSpecConstraintShapes exercises every rendering branch: range operators
// (^ ~ > <) append directly, exact = strips to @, bare numeric keeps @, star is
// bare. These match how pkgx v2.10.3 actually parses each form.
func TestDepSpecConstraintShapes(t *testing.T) {
	cases := []struct {
		project, constraint, want string
	}{
		{"cmake.org", "^3", "cmake.org^3"},
		{"cmake.org", "~3.31", "cmake.org~3.31"},
		{"gnu.org/gmp", ">=6", "gnu.org/gmp>=6"},
		{"foo", "<2", "foo<2"},
		{"foo", "3", "foo@3"},
		{"bar", "=1.2.3", "bar@1.2.3"},
		{"baz", "*", "baz"},
		{"qux", "", "qux"},
	}
	for _, c := range cases {
		if got := depSpec(c.project, c.constraint); got != c.want {
			t.Errorf("depSpec(%q,%q)=%q want %q", c.project, c.constraint, got, c.want)
		}
		if got := DepSpecs(map[string]any{c.project: c.constraint}, lin()); len(got) != 1 || got[0] != c.want {
			t.Errorf("DepSpecs %q:%q = %v want [%q]", c.project, c.constraint, got, c.want)
		}
	}
}

// TestSpecProject checks project extraction across every delimiter form so that
// EvalDeps dedup keys are stable regardless of constraint shape.
func TestSpecProject(t *testing.T) {
	for spec, want := range map[string]string{
		"cmake.org^3":    "cmake.org",
		"foo@3":          "foo",
		"gnu.org/gmp>=6": "gnu.org/gmp",
		"bar~1.2":        "bar",
		"baz<2":          "baz",
		"qux=1":          "qux",
		"plain":          "plain",
	} {
		if got := SpecProject(spec); got != want {
			t.Errorf("SpecProject(%q)=%q want %q", spec, got, want)
		}
	}
}

func TestValStr(t *testing.T) {
	cases := []struct {
		v    any
		want string
	}{{nil, "*"}, {"^1", "^1"}, {true, "*"}, {false, ""}, {5, "5"}, {3.0, "3"}}
	for _, c := range cases {
		if got := valStr(c.v); got != c.want {
			t.Errorf("valStr(%v)=%q want %q", c.v, got, c.want)
		}
	}
	// a bare-star constraint yields a bare project spec
	if g := DepSpecs(map[string]any{"p": "*"}, lin()); !reflect.DeepEqual(g, []string{"p"}) {
		t.Errorf("star = %v", g)
	}
}

func TestPlatformKey(t *testing.T) {
	for k, exp := range map[string][3]string{
		"linux":          {"linux", "", "y"},
		"x86-64":         {"", "x86-64", "y"},
		"windows/x86-64": {"windows", "x86-64", "y"},
		"openssl.org":    {"", "", ""},
	} {
		os, arch, ok := platformKey(k)
		if os != exp[0] || arch != exp[1] || (ok != (exp[2] == "y")) {
			t.Errorf("platformKey(%q)=%q,%q,%v", k, os, arch, ok)
		}
	}
}

func TestBaseToolchainAndEvalDeps(t *testing.T) {
	base := BaseToolchain()
	if len(base) == 0 || !contains(base, "gnu.org/autoconf") || !contains(base, "gnu.org/texinfo") {
		t.Errorf("base toolchain = %v", base)
	}
	// gawk is pinned to 5.3 (5.4.1 regressed autotools config-header generation,
	// e.g. libpng's pnglibconf drops PNG_SETJMP_SUPPORTED). Guard against a revert
	// to the bare/latest form, and confirm it still dedups by bare project.
	if contains(base, "gnu.org/gawk") || !contains(base, "gnu.org/gawk"+ToolchainGawk) {
		t.Errorf("gawk must be pinned to %s, got base = %v", ToolchainGawk, base)
	}
	// bison is required so autotools packages that ship a .y grammar (gettext's
	// plural.y) can regenerate the .c during the build (ylwrap → bison).
	if !contains(base, "gnu.org/bison") {
		t.Errorf("base toolchain must include gnu.org/bison, got %v", base)
	}
	if SpecProject("gnu.org/gawk@5.3") != "gnu.org/gawk" {
		t.Errorf("SpecProject should strip @5.3 for dedup")
	}
	// EvalDeps = base + runtime + build, deduped by project, sorted
	got := EvalDeps("acme.org/thing",
		map[string]any{"openssl.org": "^1.1"},
		map[string]any{"freedesktop.org/pkg-config": "^0.29"}, // already in base → dedup
		lin(),
	)
	if !contains(got, "openssl.org^1.1") || !contains(got, "gnu.org/autoconf") {
		t.Errorf("EvalDeps missing entries: %v", got)
	}
	// pkg-config appears exactly once (base's bare form wins)
	n := 0
	for _, s := range got {
		if strings.HasPrefix(s, "freedesktop.org/pkg-config") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("pkg-config not deduped: %v", got)
	}
	// sorted
	if !sortedStrings(got) {
		t.Errorf("EvalDeps not sorted: %v", got)
	}
}

func TestDepTokens(t *testing.T) {
	resolve := func(p, c string) (string, error) { return "1.2.3", nil }
	toks, _, err := DepTokens(
		map[string]any{"openssl.org": "^1.1"},
		map[string]any{"freedesktop.org/pkg-config": "^0.29"},
		lin(), "/opt/pkgx", resolve)
	if err != nil {
		t.Fatal(err)
	}
	find := func(from string) (string, bool) {
		for _, tk := range toks {
			if tk.From == from {
				return tk.To, true
			}
		}
		return "", false
	}
	if to, ok := find("deps.openssl.org.prefix"); !ok || to != filepath.FromSlash("/opt/pkgx/openssl.org/v1.2.3") {
		t.Errorf("openssl prefix = %q %v", to, ok)
	}
	if to, _ := find("deps.openssl.org.version"); to != "1.2.3" {
		t.Errorf("openssl version = %q", to)
	}
	if _, ok := find("deps.freedesktop.org/pkg-config.prefix"); !ok {
		t.Error("build dep pkg-config token missing")
	}
	// resolve error propagates
	if _, _, err := DepTokens(map[string]any{"x": "1"}, nil, lin(), "/p", func(string, string) (string, error) { return "", errBoom }); err == nil {
		t.Error("expected resolve error")
	}
	// empty deps → no tokens
	if tk, _, _ := DepTokens(nil, nil, lin(), "/p", resolve); len(tk) != 0 {
		t.Errorf("empty = %v", tk)
	}
}

func TestSanitizedEnv(t *testing.T) {
	t.Setenv("TERM", "xterm")
	t.Setenv("GITHUB_TOKEN", "secret")
	// Where the build's own `pkgx +deps` resolves from: a local registry cache
	// and a corrected overlay only apply if they survive the sanitised env.
	t.Setenv("ZPKG_DIST", "oci://http://cache:5111/go-zpkg/packages")
	t.Setenv("ZPKG_PANTRY", "https://pantry.example/projects")
	t.Setenv("ZPKG_PANTRY_OVERLAY", "https://overlay.example/projects")
	// The opt-out a test harness needs when it points at unsigned fixtures.
	t.Setenv("ZPKG_VERIFY", "0")
	os.Unsetenv("ZPKG_PANTRY_DIR")
	env := SanitizedEnv("/h", "/pkgx")
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/h", "ZPKG_DIR=/pkgx", "TERM=xterm", "MAKEFLAGS=ACLOCAL=true AUTOMAKE=true AUTOCONF=true AUTOHEADER=true AUTOPOINT=true", "FORCE_UNSAFE_CONFIGURE=1", "ZPKG_DIST=oci://http://cache:5111/go-zpkg/packages", "ZPKG_PANTRY=https://pantry.example/projects", "ZPKG_PANTRY_OVERLAY=https://overlay.example/projects", "ZPKG_VERIFY=0"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SanitizedEnv missing %q in %v", want, env)
		}
	}
	if strings.Contains(joined, "ZPKG_PANTRY_DIR") {
		t.Error("unset var leaked into SanitizedEnv")
	}

	// A build script is third-party code running as root, and the workflow's
	// token carries `packages: write` on the organisation. Measured on a
	// fresh pantry: 1899 recipes, 2 reference GITHUB_TOKEN, BOTH in their
	// `test:` block, 0 in our overlay — and bk's own fetcher never sends it.
	// So no build wants it, and `bk test` adds it where the need is.
	for _, e := range env {
		if strings.HasPrefix(e, "GITHUB_TOKEN=") || strings.HasPrefix(e, "GH_TOKEN=") {
			t.Errorf("a write-capable token reached the build script's environment: %q", e)
		}
	}
}

func TestTouchAutotools(t *testing.T) {
	dir := t.TempDir()
	files := []string{"configure.ac", "acinclude.m4", "m4/pkg.m4", "aclocal.m4", "config.h.in", "configure", "Makefile.in", "sub/Makefile.in"}
	for _, f := range files {
		p := filepath.Join(dir, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("x"), 0o644)
	}
	if err := TouchAutotools(dir); err != nil {
		t.Fatal(err)
	}
	mt := func(f string) time.Time {
		fi, _ := os.Stat(filepath.Join(dir, f))
		return fi.ModTime()
	}
	// ascending tiers: inputs (incl. m4/ macros) < aclocal.m4 < configure < Makefile.in
	if !mt("m4/pkg.m4").Before(mt("aclocal.m4")) {
		t.Errorf("m4/ macro not aged before aclocal.m4: m4=%v aclocal=%v", mt("m4/pkg.m4"), mt("aclocal.m4"))
	}
	if !mt("configure.ac").Before(mt("aclocal.m4")) ||
		!mt("aclocal.m4").Before(mt("configure")) ||
		!mt("configure").Before(mt("Makefile.in")) ||
		!mt("configure").Before(mt("sub/Makefile.in")) {
		t.Errorf("mtimes not ascending: ac=%v aclocal=%v configure=%v mk=%v",
			mt("configure.ac"), mt("aclocal.m4"), mt("configure"), mt("Makefile.in"))
	}
}

func TestTouchAutotoolsErrors(t *testing.T) {
	// walk error: a non-existent dir
	if err := TouchAutotools(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected walk error on missing dir")
	}
	// chtimes error via the seam
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "configure.ac"), []byte("x"), 0o644)
	old := osChtimes
	defer func() { osChtimes = old }()
	osChtimes = func(string, time.Time, time.Time) error { return os.ErrPermission }
	if err := TouchAutotools(dir); err == nil {
		t.Error("expected chtimes seam error")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func sortedStrings(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i-1] > ss[i] {
			return false
		}
	}
	return true
}

// TestEvalDepsRecipeConstraintBeatsBase: the base toolchain is a floor, not a
// pin. gnu.org/texinfo declares `perl.org: ~5.42` because its XS modules are
// compiled against that perl; when the base's unconstrained perl.org won, every
// recipe running makeinfo died with "Perl API version v5.42.0 … does not match
// v5.44.0". A recipe must be able to constrain a base project.
func TestEvalDepsRecipeConstraintBeatsBase(t *testing.T) {
	got := EvalDeps("acme.org/thing", map[string]any{"perl.org": "~5.42"}, nil, lin())
	var perl []string
	for _, s := range got {
		if SpecProject(s) == "perl.org" {
			perl = append(perl, s)
		}
	}
	if len(perl) != 1 || perl[0] != "perl.org~5.42" {
		t.Fatalf("perl specs = %v, want exactly [perl.org~5.42]", perl)
	}
	// a BUILD dep constrains it just as well
	got = EvalDeps("acme.org/thing", nil, map[string]any{"gnu.org/gawk": "^5.4"}, lin())
	if !contains(got, "gnu.org/gawk^5.4") || contains(got, "gnu.org/gawk"+ToolchainGawk) {
		t.Errorf("a build dep must override the base's gawk pin: %v", got)
	}
	// …and a project the recipe says nothing about still comes from the base,
	// with the base's own pin intact.
	if !contains(EvalDeps("acme.org/thing", nil, nil, lin()), "gnu.org/gawk"+ToolchainGawk) {
		t.Error("the base pin must survive when the recipe is silent")
	}
}

// TestBaseToolchainPinsPerl: the base toolchain and the XS-bearing tools inside
// it have to agree, and the pin must be STATED, not left to whatever is newest.
//
// This test used to assert the pin equalled the literal "~5.42" — texinfo's
// constraint on the day it was written. texinfo moved to ~5.44 and the literal
// did not, so the test went on passing while help2man refused to load its own
// Locale::gettext under the pinned perl. Comparing against a copy is not
// comparing; the copy is checked by TestCheckToolchainPerl instead, which reads
// the recipe.
func TestBaseToolchainPinsPerl(t *testing.T) {
	base := BaseToolchain()
	if !contains(base, "perl.org"+ToolchainPerl) || contains(base, "perl.org") {
		t.Errorf("perl must be pinned to %s, got %v", ToolchainPerl, base)
	}
	// a recipe still wins over the pin
	if got := EvalDeps("acme.org/thing", map[string]any{"perl.org": "^5.99"}, nil, lin()); !contains(got, "perl.org^5.99") || contains(got, "perl.org"+ToolchainPerl) {
		t.Errorf("a recipe must override the base perl pin: %v", got)
	}
}

// writeRecipe lays out projects/<proj>/package.yml under a throwaway pantry.
func writeRecipe(t *testing.T, root, proj, body string) {
	t.Helper()
	dir := filepath.Join(root, "projects", filepath.FromSlash(proj))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const recipeWithPerl = `distributable:
  url: https://example.com/x-{{ version }}.tar.gz
versions:
  github: acme/x
dependencies:
  perl.org: %s
build:
  script: make
test: true
`

// TestCheckToolchainPerl: the check the old test only claimed to be. It reads
// what the recipe declares, so a recipe moving is something it can SEE.
func TestCheckToolchainPerl(t *testing.T) {
	t.Run("agreeing", func(t *testing.T) {
		root := t.TempDir()
		for _, p := range perlXSToolchainProjects {
			writeRecipe(t, root, p, fmt.Sprintf(recipeWithPerl, ToolchainPerl))
		}
		if problems := CheckToolchainPerl(nil, root); len(problems) != 0 {
			t.Errorf("reported %v for recipes that agree with the pin", problems)
		}
	})
	t.Run("one recipe has moved", func(t *testing.T) {
		root := t.TempDir()
		writeRecipe(t, root, perlXSToolchainProjects[0], fmt.Sprintf(recipeWithPerl, "~5.46"))
		writeRecipe(t, root, perlXSToolchainProjects[1], fmt.Sprintf(recipeWithPerl, ToolchainPerl))
		problems := CheckToolchainPerl(nil, root)
		if len(problems) != 1 {
			t.Fatalf("reported %d problem(s), want 1: %v", len(problems), problems)
		}
		for _, want := range []string{perlXSToolchainProjects[0], "~5.46", ToolchainPerl} {
			if !strings.Contains(problems[0].Error(), want) {
				t.Errorf("problem does not name %q: %v", want, problems[0])
			}
		}
	})
	t.Run("a recipe that is not there", func(t *testing.T) {
		// A pantry need not be complete. Refusing to build over a missing file
		// would be a worse failure than the one this prevents.
		if problems := CheckToolchainPerl(nil, t.TempDir()); len(problems) != 0 {
			t.Errorf("reported %v for an empty pantry", problems)
		}
	})
	t.Run("a recipe that names no perl", func(t *testing.T) {
		root := t.TempDir()
		writeRecipe(t, root, perlXSToolchainProjects[0], `distributable:
  url: https://example.com/x-{{ version }}.tar.gz
versions:
  github: acme/x
build:
  script: make
test: true
`)
		if problems := CheckToolchainPerl(nil, root); len(problems) != 0 {
			t.Errorf("reported %v for a recipe with no perl constraint", problems)
		}
	})
	t.Run("a recipe we cannot read", func(t *testing.T) {
		root := t.TempDir()
		writeRecipe(t, root, perlXSToolchainProjects[0], "versions: [1, 2\n")
		if problems := CheckToolchainPerl(nil, root); len(problems) != 1 {
			t.Errorf("want the parse failure reported, got %v", problems)
		}
	})
}

// TestBaseToolchainHasHelp2man: autotools recipes generate man pages with
// help2man through build-aux/missing. It has to be in the EVAL, not merely on
// PATH: pkgx only exports a package's runtime env for packages in the closure,
// and help2man publishes the PERL5LIB that finds the Locale::gettext it bundles.
// Without that, help2man runs and dies with "Can't locate Locale/gettext.pm".
func TestBaseToolchainHasHelp2man(t *testing.T) {
	if !contains(BaseToolchain(), "gnu.org/help2man") {
		t.Errorf("base toolchain must include gnu.org/help2man, got %v", BaseToolchain())
	}
}

// TestSanitizedEnvPassesCacheAndQemu: two variables that must survive the
// sanitised environment, each for a reason that was measured rather than
// assumed.
//
// ZPKG_CACHE names a distribution point, like ZPKG_DIST beside it: dropping it
// sends the `pkgx +deps` line of every generated script past the pull-through
// cache the job was configured to use.
//
// QEMU_RESERVED_VA matters when the target is emulated. Our gnu.org/bash is
// built with bash's own sbrk-based malloc, and under qemu-user's default
// reserved address space it cannot allocate at all —
//
//	/bin/sh: xmalloc: setlinebuf.c:51: cannot allocate 2016 bytes (0 bytes allocated)
//
// on the first command of the build. In an emulated container our bash fails,
// the same bash with QEMU_RESERVED_VA set succeeds, and the distribution's bash
// (built --without-bash-malloc) never had the problem.
func TestSanitizedEnvPassesCacheAndQemu(t *testing.T) {
	t.Setenv("ZPKG_CACHE", "oci://http://10.0.0.1:5111/go-zpkg/packages")
	t.Setenv("QEMU_RESERVED_VA", "0x100000000")
	env := SanitizedEnv("/root", "/pkgx")
	for _, want := range []string{
		"ZPKG_CACHE=oci://http://10.0.0.1:5111/go-zpkg/packages",
		"QEMU_RESERVED_VA=0x100000000",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("sanitised env dropped %q", want)
		}
	}
	// The guard the allow-list exists for is unchanged: ambient host toolchain
	// state still does not travel.
	t.Setenv("HOMEBREW_PREFIX", "/opt/homebrew")
	for _, got := range SanitizedEnv("/root", "/pkgx") {
		if strings.HasPrefix(got, "HOMEBREW_PREFIX=") {
			t.Error("sanitised env leaked HOMEBREW_PREFIX")
		}
	}
}

// A package's own published bottle must not join the toolchain of its own
// build. It would shadow the thing being built with an older copy — and when
// that copy cannot start, the package can no longer be repaired at all:
// gnu.org/grep's own configure refuses with "no working 'grep' found", so the
// broken bottle blocked the build that would have replaced it.
func TestOwnBottleIsNotInItsOwnToolchain(t *testing.T) {
	got := EvalDeps("gnu.org/grep", nil, nil, lin())
	for _, s := range got {
		if SpecProject(s) == "gnu.org/grep" {
			t.Fatalf("grep's own build got grep from the base toolchain: %v", got)
		}
	}
	// The rest of the floor is untouched — this removes one entry, not the list.
	if !contains(got, "gnu.org/sed") || !contains(got, "gnu.org/coreutils") {
		t.Errorf("the base toolchain lost more than the package itself: %v", got)
	}
	// And another package still gets grep.
	other := EvalDeps("acme.org/thing", nil, nil, lin())
	if !contains(other, "gnu.org/grep") {
		t.Errorf("grep vanished from an unrelated build: %v", other)
	}
}

// A recipe that names itself is stating something we have no business
// overruling: only the base toolchain is filtered.
func TestARecipeMayStillNameItself(t *testing.T) {
	got := EvalDeps("gnu.org/grep", nil, map[string]any{"gnu.org/grep": "^3"}, lin())
	if !contains(got, "gnu.org/grep^3") {
		t.Errorf("a recipe's own explicit build dep was dropped: %v", got)
	}
}

// TestPlatformKeyReadsEveryArchBothWays pins the invariant that made
// osArchDepRE derived rather than written out.
//
// A recipe key reaches platformKey in two spellings -- `linux/s390x` through
// the regex, bare `s390x` through the map -- and the two used to be written
// separately a line apart. Falling behind in one of them does not raise
// anything: platformKey returns ok=false, reduceDepMap treats the key as a
// project name, and the recipe acquires a dependency on a project called after
// an architecture. This walks the maps, so it fails the moment a new arch is
// legal in one door and not the other.
func TestPlatformKeyReadsEveryArchBothWays(t *testing.T) {
	for arch := range arches {
		if _, got, ok := platformKey(arch); !ok || got != arch {
			t.Errorf("platformKey(%q) = %q, %v; want the arch, true", arch, got, ok)
		}
		for plat := range platforms {
			k := plat + "/" + arch
			gotOS, gotArch, ok := platformKey(k)
			if !ok || gotOS != plat || gotArch != arch {
				t.Errorf("platformKey(%q) = %q, %q, %v; want %q, %q, true", k, gotOS, gotArch, ok, plat, arch)
			}
		}
	}
}

// TestPlatformKeyRejectsAnArchItDoesNotHave: the derived pattern must still
// refuse, or every unknown key would read as a platform key instead of a
// project name.
func TestPlatformKeyRejectsAnArchItDoesNotHave(t *testing.T) {
	for _, k := range []string{"linux/riscv64", "riscv64", "linux/", "/s390x", "linux/s390x/extra"} {
		if _, _, ok := platformKey(k); ok {
			t.Errorf("platformKey(%q) = ok; want it read as a project name", k)
		}
	}
}

// HostPrefixForSelfDep answers only when the recipe and the host AGREE, and
// the disagreements are the point: a guessed prefix would send a compiler
// somewhere nobody chose, and every one of these shapes was reachable.
func TestHostPrefixForSelfDep(t *testing.T) {
	at := func(m map[string]string) func(string) (string, error) {
		return func(name string) (string, error) {
			if p, ok := m[name]; ok {
				return p, nil
			}
			return "", errors.New("not found")
		}
	}
	for name, c := range map[string]struct {
		provides any
		host     map[string]string
		want     string // "" = no token
	}{
		"the recipe and the host agree": {
			[]any{"bin/sed"}, map[string]string{"sed": "/usr/bin/sed"}, "/usr",
		},
		"a deeper prefix is still a prefix": {
			[]any{"bin/sed"}, map[string]string{"sed": "/opt/local/bin/sed"}, "/opt/local",
		},
		// The host has it, but not at <prefix>/bin. There is no prefix that
		// makes both statements true, so there is no answer to give.
		"the binary is not under a bin/": {
			[]any{"bin/sed"}, map[string]string{"sed": "/sbin/sed"}, "",
		},
		"the host does not have it": {
			[]any{"bin/sed"}, map[string]string{}, "",
		},
		// The first candidate is absent and the second is there: a recipe
		// providing several binaries is answered by whichever one the host can
		// actually confirm.
		"the second provided binary answers": {
			[]any{"bin/absent", "bin/sed"}, map[string]string{"sed": "/usr/bin/sed"}, "/usr",
		},
		// Nothing in `provides:` is a binary, so the recipe never claimed to
		// put anything on a PATH and the host cannot confirm a thing.
		"a library provides no binary": {
			[]any{"lib/libsed.a"}, map[string]string{"sed": "/usr/bin/sed"}, "",
		},
		"provides is a platform mapping, not a list": {
			map[string]any{"linux": []any{"bin/sed"}}, map[string]string{"sed": "/usr/bin/sed"}, "",
		},
		"provides holds something that is not a string": {
			[]any{3}, map[string]string{"sed": "/usr/bin/sed"}, "",
		},
		"no provides at all": {nil, map[string]string{"sed": "/usr/bin/sed"}, ""},
	} {
		got := HostPrefixForSelfDep("gnu.org/sed", c.provides, at(c.host))
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: want no token, got %v", name, got)
			}
			continue
		}
		if len(got) != 1 || got[0].From != "deps.gnu.org/sed.prefix" || got[0].To != c.want {
			t.Errorf("%s: got %v, want deps.gnu.org/sed.prefix = %s", name, got, c.want)
		}
	}
	// No way to ask is not the same as an answer of "/".
	if got := HostPrefixForSelfDep("gnu.org/sed", []any{"bin/sed"}, nil); got != nil {
		t.Errorf("without a lookup there is nothing to confirm: %v", got)
	}
}

// The defect the test above could not see: it creates every file at NOW, so a
// generated file this function does not know the name of comes out newer than
// its prerequisites by accident, and the ordering assertion passes.
//
// A release tarball's files are old. Then the tiers rejuvenate the INPUTS to
// within the last hour while an unknown generated file keeps its tarball
// mtime, and the function does the exact opposite of its job. On rsync-3.5.1,
// whose generated script is `configure.sh`:
//
//	configure.ac   2026-09-28 06:56:48
//	aclocal.m4     2026-09-28 06:57:48
//	configure.sh   2026-09-21 05:55:19   ← seven days STALE
//
// make regenerated it with whatever autoconf was present and rsync's Makefile
// stopped the build: "configure.sh has CHANGED."
func TestTouchAutotoolsOnATarballsOldTimestamps(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().AddDate(0, 0, -7)
	for _, f := range []string{"configure.ac", "aclocal.m4", "config.h.in", "configure", "configure.sh", "Makefile.in"} {
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := TouchAutotools(dir); err != nil {
		t.Fatal(err)
	}
	mt := func(f string) time.Time {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		return fi.ModTime()
	}
	// Every generated configure script, by every name a tarball gives it, must
	// end up newer than the inputs make would regenerate it from.
	for _, gen := range []string{"configure", "configure.sh"} {
		if !mt("aclocal.m4").Before(mt(gen)) {
			t.Errorf("%s (%v) is not newer than aclocal.m4 (%v) — make will regenerate it",
				gen, mt(gen), mt("aclocal.m4"))
		}
		if !mt("configure.ac").Before(mt(gen)) {
			t.Errorf("%s (%v) is not newer than configure.ac (%v)", gen, mt(gen), mt("configure.ac"))
		}
	}
}

// TestTouchAutotoolsOnGlibcsPreconfigure. glibc's sysdeps/*/preconfigure is a
// generated file like configure, and until it was listed as one the s390x seed
// died on a message about a machine glibc has supported for decades:
//
//	configure: error: The s390x is not supported.
//
// The shape here is the one measured in glibc-2.44.tar.xz: aclocal.m4,
// sysdeps/s390/preconfigure.ac and sysdeps/s390/preconfigure all carry ONE
// tarball mtime. Rejuvenating aclocal.m4 and leaving the preconfigure alone
// makes the prerequisite newer than its target, make runs
// `$(AUTOCONF) … > $@.new; mv -f $@.new $@`, and bk's own AUTOCONF=true writes
// an EMPTY file over the four lines that turn $machine into s390/s390-64.
//
// glibc 2.42 had ten preconfigure.ac files and 2.44 has eleven: s390's is the
// new one, which is why this only started failing now.
func TestTouchAutotoolsOnGlibcsPreconfigure(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sysdeps", "s390")
	if err := os.MkdirAll(sys, 0o755); err != nil {
		t.Fatal(err)
	}
	// One mtime for everything, as a tarball gives it.
	old := time.Date(2026, 7, 24, 15, 16, 0, 0, time.UTC)
	files := map[string]string{
		filepath.Join(dir, "aclocal.m4"):      "x",
		filepath.Join(dir, "configure.ac"):    "x",
		filepath.Join(dir, "configure"):       "x",
		filepath.Join(sys, "preconfigure.ac"): "x",
		filepath.Join(sys, "preconfigure"):    "x",
	}
	for p, b := range files {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := TouchAutotools(dir); err != nil {
		t.Fatal(err)
	}
	mt := func(p string) time.Time {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.ModTime()
	}
	pre := filepath.Join(sys, "preconfigure")
	// Newer than BOTH prerequisites of `%/preconfigure: %/preconfigure.ac aclocal.m4`.
	for _, prereq := range []string{filepath.Join(dir, "aclocal.m4"), filepath.Join(sys, "preconfigure.ac")} {
		if !mt(prereq).Before(mt(pre)) {
			t.Errorf("preconfigure (%v) is not newer than %s (%v) — make will regenerate it, and AUTOCONF=true will empty it",
				mt(pre), filepath.Base(prereq), mt(prereq))
		}
	}
	// And preconfigure.ac must stay in the INPUTS tier: an exact name cannot
	// claim it, and dragging it up here would defeat the whole ordering.
	if !mt(filepath.Join(sys, "preconfigure.ac")).Before(mt(filepath.Join(dir, "aclocal.m4")).Add(time.Second)) {
		t.Errorf("preconfigure.ac was pulled out of the inputs tier")
	}
}

// ⛔⛔ THE RESOLVED LIST MUST REACH THE CALLER, not just the tokens.
//
// DepTokens computed project+version+prefix for the whole build and runtime
// closure on every build and discarded it, which is why a published bottle
// could not say what compiled it. A test of the ATTESTATION alone stays green
// when this plumbing is severed — proved by a mutation that returned nil here
// and was caught by nothing until this test existed.
func TestDepTokensReturnsWhatItResolved(t *testing.T) {
	resolve := func(p, c string) (string, error) {
		if p == "go.dev" {
			return "1.27.2", nil
		}
		return "1.2.3", nil
	}
	_, deps, err := DepTokens(
		map[string]any{"openssl.org": "^1.1"},
		map[string]any{"go.dev": "^1.27"},
		lin(), "/opt/pkgx", resolve)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("resolved %d deps, want 2: %+v", len(deps), deps)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Project] = d.Version
	}
	// RUNTIME AND BUILD DEPENDENCIES BOTH: the compiler is a build dep, and a
	// list that held only the runtime half would miss the one axis a
	// toolchain rebuild moves along.
	if got["go.dev"] != "1.27.2" {
		t.Errorf("the compiler is not in the resolved list: %+v", deps)
	}
	if got["openssl.org"] != "1.2.3" {
		t.Errorf("the runtime dependency is missing: %+v", deps)
	}
	// Sorted, so two builds of the same closure render identically.
	if deps[0].Project > deps[1].Project {
		t.Errorf("the resolved list is not sorted: %+v", deps)
	}
	// And no deps means no list, rather than a list of nothing.
	if _, none, _ := DepTokens(nil, nil, lin(), "/p", resolve); len(none) != 0 {
		t.Errorf("empty deps produced %+v", none)
	}
}
