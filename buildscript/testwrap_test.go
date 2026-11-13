package buildscript

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

func linuxHost() target.Target {
	return target.Target{Platform: "linux", Arch: "x86-64", Triple: "x86_64-linux-gnu"}
}

func TestWrapTestRunsThePackageInAnEmptySandbox(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "gawk --version | grep 5.4.1",
		Package:    "gnu.org/gawk@5.4.1",
		Deps:       []string{"gnu.org/diffutils"},
		Home:       "/bk/home", Sandbox: "/bk/testbed",
		ZpkgDir: "/opt/pkgx", ZpkgxBin: "/opt/pkgx/bin/pkgx", BashPath: "/opt/bash",
		Host: linuxHost(),
	})
	wants := []string{
		"#!/opt/bash\n",
		"set -e",
		`export HOME="/bk/home"`,
		`export ZPKG_DIR="/opt/pkgx"`,
		`export TMPDIR="$HOME/tmp"; mkdir -p "$TMPDIR"`,
		`__bk_deps_env="$(CLICOLOR_FORCE=1 /opt/pkgx/bin/pkgx "+gnu.org/gawk@5.4.1" "+gnu.org/diffutils")" || {`,
		// ⛔ THIS ASSERTION WAS STALE AND PASSED ANYWAY. It read `bk: …` from
		// before the bk→zbk rename, and kept matching because "zbk" CONTAINS
		// "bk" — a substring assertion cannot tell the two apart. Renaming to
		// zpkb broke the coincidence and exposed it.
		`zpkb: the test environment failed`,
		`export ZPKGX="/opt/pkgx/bin/pkgx"`,
		`cd "/bk/testbed"`,
		"gawk --version | grep 5.4.1",
	}
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
}

// A test compiles nothing and links nothing, so the build's flags and its
// default compiler must not be there. A test that passed because CFLAGS
// pointed at the store would be answering a question nobody asked.
func TestWrapTestHasNoneOfTheBuildsToolchain(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "true", Package: "zlib.net@1.3.2",
		Home: "/h", Sandbox: "/box", ZpkgDir: "/opt/pkgx", ZpkgxBin: "pkgx",
		Host: linuxHost(),
	})
	for _, forbidden := range []string{
		"CFLAGS", "CXXFLAGS", "LDFLAGS", "CMAKE_PREFIX_PATH", "+llvm.org", "SRCROOT",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("test script carries the build's %s:\n%s", forbidden, s)
		}
	}
}

// The package under test leads the eval so a test dependency's closure cannot
// put another version of the same project ahead of it on PATH.
func TestWrapTestPutsThePackageUnderTestFirst(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "true", Package: "p@1", Deps: []string{"a", "b"},
		Home: "/h", Sandbox: "/box", ZpkgxBin: "pkgx", Host: linuxHost(),
	})
	want := `pkgx "+p@1" "+a" "+b"`
	if !strings.Contains(s, want) {
		t.Errorf("want %q in:\n%s", want, s)
	}
}

// A recipe may name no test dependency at all, and most do not. The eval then
// carries the package alone — not an empty `pkgx` with no arguments, which
// would succeed and give the test nothing.
func TestWrapTestWithNoDepsStillInstallsThePackage(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "true", Package: "p@1",
		Home: "/h", Sandbox: "/box", ZpkgxBin: "pkgx", Host: linuxHost(),
	})
	if !strings.Contains(s, `pkgx "+p@1"`) {
		t.Errorf("the package is not in the eval:\n%s", s)
	}
}

func TestWrapTestDefaultsBashAndZpkgx(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "true", Package: "p@1", Home: "/h", Sandbox: "/box", Host: linuxHost(),
	})
	if !strings.HasPrefix(s, "#!/bin/bash\n") {
		t.Errorf("want the default shebang, got:\n%s", s)
	}
	if !strings.Contains(s, `pkgx "+p@1"`) {
		t.Errorf("want the default pkgx, got:\n%s", s)
	}
	// With no ZpkgxBin there is nothing to export as $ZPKGX; a recipe that reads
	// it would otherwise get an empty string that looks like a path.
	if strings.Contains(s, "export ZPKGX=") {
		t.Errorf("exported an empty ZPKGX:\n%s", s)
	}
	// Nor an empty ZPKG_DIR, for the same reason.
	if strings.Contains(s, "export ZPKG_DIR=") {
		t.Errorf("exported an empty ZPKG_DIR:\n%s", s)
	}
}

// testPlus with nothing at all: `writeDepEval` must emit no eval rather than
// `pkgx ` with no arguments.
func TestWrapTestWithNothingToInstallEmitsNoEval(t *testing.T) {
	s := WrapTest(TestWrapOptions{UserScript: "true", Home: "/h", Sandbox: "/box", Host: linuxHost()})
	if strings.Contains(s, "__bk_deps_env") {
		t.Errorf("emitted an eval with nothing to install:\n%s", s)
	}
}

// 260 recipes' tests compile. A sandbox that refuses a compiler reports them
// all as failing packages.
func TestWrapTestAsksForACompilerWhenTheTestCompiles(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "cc test.c -lz", Package: "zlib.net@1.3.2", Compiler: true,
		Home: "/h", Sandbox: "/box", ZpkgxBin: "pkgx", Host: linuxHost(),
	})
	if !strings.Contains(s, `"+llvm.org"`) {
		t.Errorf("no compiler in the eval:\n%s", s)
	}
	// After the recipe's own, so a recipe that names a compiler keeps its
	// version.
	if i, j := strings.Index(s, `"+zlib.net@1.3.2"`), strings.Index(s, `"+llvm.org"`); i > j {
		t.Errorf("the compiler came before the package under test:\n%s", s)
	}
}

func TestWrapTestAsksForNoCompilerWhenTheTestDoesNot(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "gawk --version", Package: "gnu.org/gawk@5.4.1",
		Home: "/h", Sandbox: "/box", ZpkgxBin: "pkgx", Host: linuxHost(),
	})
	if strings.Contains(s, "llvm.org") {
		t.Errorf("installed a compiler for a test that compiles nothing:\n%s", s)
	}
}

// darwin builds with the system toolchain and Wrap makes the same exception;
// adding llvm.org there would give the test a compiler the build never used.
func TestWrapTestTakesDarwinsCompilerFromTheHost(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "cc test.c", Package: "p@1", Compiler: true,
		Home: "/h", Sandbox: "/box", ZpkgxBin: "pkgx",
		Host: target.Target{Platform: "darwin", Arch: "aarch64"},
	})
	if strings.Contains(s, "llvm.org") {
		t.Errorf("darwin must not pull llvm.org:\n%s", s)
	}
}

// The test eval exits with EnvFailExit, the build's with 1. The caller can
// then tell "I could not assemble the environment" from "the thing I ran
// said no" — five of nine failures in the s390x seed's first sweep were the
// former, and were reported as the latter.
func TestWrapTestEnvFailureHasItsOwnExitStatus(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "true", Package: "p@1",
		Home: "/h", Sandbox: "/box", ZpkgxBin: "pkgx", Host: linuxHost(),
	})
	if !strings.Contains(s, "exit 69") {
		t.Errorf("the test eval does not carry EnvFailExit:\n%s", s)
	}
	if strings.Contains(s, "  exit 1\n") {
		t.Errorf("the test eval still exits 1:\n%s", s)
	}
	b := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"zlib.net"},
		Target: linuxHost(), Host: linuxHost(), ZpkgxBin: "pkgx",
	})
	if !strings.Contains(b, "  exit 1\n") {
		t.Errorf("a BUILD must still exit 1 — the distinction is no use to it:\n%s", b)
	}
	if strings.Contains(b, "exit 69") {
		t.Errorf("a build took the test's status:\n%s", b)
	}
}

// pipefail is a BUILD's rule. A test is a list of assertions and
// `cmd | head -1` is how several read one line; under pipefail the producer
// takes SIGPIPE when head closes and the assertion fails for writing too
// much. 38 of the pantry's 1897 test blocks pipe into head or tail.
func TestWrapTestDoesNotSetPipefail(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: "true", Package: "p@1", Home: "/h", Sandbox: "/box", Host: linuxHost(),
	})
	if strings.Contains(s, "pipefail") {
		t.Errorf("a test script must not set pipefail:\n%s", s)
	}
	if !strings.Contains(s, "set -e\n") {
		t.Errorf("set -e is still wanted:\n%s", s)
	}
	// A build keeps it: there the rule is right.
	b := Wrap(WrapOptions{UserScript: "make", Target: linuxHost(), Host: linuxHost()})
	if !strings.Contains(b, "set -eo pipefail") {
		t.Errorf("a build must keep pipefail:\n%s", b)
	}
}

// The xtrace goes to stderr, and 31 of the pantry's test blocks capture
// stderr into a substitution — so a trace would become the value they test.
// gnu.org/glibc reported a broken iconv on nothing else.
func TestWrapTestDoesNotTrace(t *testing.T) {
	s := WrapTest(TestWrapOptions{
		UserScript: `out=$(iconv --version 2>&1 | head -1)`, Package: "p@1",
		Home: "/h", Sandbox: "/box", Host: linuxHost(),
	})
	if strings.Contains(s, "set -x") {
		t.Errorf("a test script must not trace into what it captures:\n%s", s)
	}
	// A build still traces: nothing there captures its own stderr.
	b := Wrap(WrapOptions{UserScript: "make", Target: linuxHost(), Host: linuxHost()})
	if !strings.Contains(b, "set -x") {
		t.Errorf("a build must keep its trace:\n%s", b)
	}
}

// Nineteen of the twenty-seven gen1 test failures were the sandbox and not
// the package: clang with no libc reports `'stdlib.h' file not found` and
// `C compiler cannot create executables`, and the assertion never ran.
func TestATestThatCompilesGetsALibcOnLinux(t *testing.T) {
	linux := target.Target{Platform: "linux", Arch: "x86-64"}
	got := WrapTest(TestWrapOptions{
		UserScript: "cc t.c -lz && ./a.out",
		Package:    "zlib.net@1.3.1",
		Compiler:   true,
		Host:       linux,
		Home:       "/h", Sandbox: "/s", ZpkgDir: "/pkgx",
	})

	// The compiler alone is not enough: it needs headers, crt files, an `ar`
	// that is not llvm-ar, and a C++ runtime.
	for _, want := range []string{`"+llvm.org"`, `"+gnu.org/glibc"`,
		`"+kernel.org/linux-headers"`, `"+gnu.org/binutils"`, `"+libcxx.llvm.org"`} {
		if !strings.Contains(got, want) {
			t.Errorf("the environment does not ask for %s", want)
		}
	}

	// The sysroot is applied only where there is no system one. This is the
	// whole reason a distribution's behaviour does not change.
	if !strings.Contains(got, `if [ ! -e /usr/include/stdlib.h ]; then`) {
		t.Error("the sysroot is not guarded by the absence of a system libc")
	}
	// CC must be set INSIDE the guard, never above it.
	guard := strings.Index(got, "if [ ! -e /usr/include/stdlib.h ]")
	cc := strings.Index(got, `export CC=`)
	if cc < 0 || cc < guard {
		t.Errorf("CC is set outside the guard (guard at %d, CC at %d)", guard, cc)
	}
	if fi := strings.Index(got[guard:], "\nfi\n"); fi >= 0 && guard+fi < cc {
		t.Error("CC is set after the guard closes")
	}
}

// What the test wrapper must still NOT have. The file's own contract: a test
// gets a compiler, not the flags that made the artefact link — otherwise a
// bottle whose headers or rpath are wrong would pass.
func TestTheSysrootCarriesNoRecipeFlags(t *testing.T) {
	got := WrapTest(TestWrapOptions{
		UserScript: "cc t.c",
		Compiler:   true,
		Host:       target.Target{Platform: "linux", Arch: "x86-64"},
		Home:       "/h", Sandbox: "/s", ZpkgDir: "/pkgx",
	})
	for _, forbidden := range []string{"CMAKE_PREFIX_PATH", "-Wl,-rpath", "$SRCROOT"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the test wrapper leaked %s, which would mask a broken bottle", forbidden)
		}
	}
}

// A test that compiles nothing installs nothing to not use.
func TestATestThatCompilesNothingGetsNoToolchain(t *testing.T) {
	got := WrapTest(TestWrapOptions{
		UserScript: "zlib-flate --version",
		Compiler:   false,
		Host:       target.Target{Platform: "linux", Arch: "x86-64"},
		Home:       "/h", Sandbox: "/s", ZpkgDir: "/pkgx",
	})
	for _, unwanted := range []string{`"+llvm.org"`, `"+gnu.org/glibc"`, "/usr/include/stdlib.h"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("a test that compiles nothing asked for %s", unwanted)
		}
	}
}

// darwin builds with the system toolchain, and Wrap makes the same exception.
func TestDarwinGetsNeitherCompilerNorSysroot(t *testing.T) {
	got := WrapTest(TestWrapOptions{
		UserScript: "cc t.c",
		Compiler:   true,
		Host:       target.Target{Platform: "darwin", Arch: "aarch64"},
		Home:       "/h", Sandbox: "/s", ZpkgDir: "/pkgx",
	})
	for _, unwanted := range []string{`"+llvm.org"`, `"+gnu.org/glibc"`, "/usr/include/stdlib.h"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("darwin asked for %s", unwanted)
		}
	}
}

// The measurement that produced this: 16 of the second sovereign
// generation's 23 test failures were a missing C header, and every one of
// them called the compiler BY NAME. `bk tools --scope test --all` counts
// cc 194, c++ 38, gcc 13, g++ 7 — command names in command position, not one
// of them reading $CC. Exporting CC was a fix that could not work.
func TestATestThatCallsCcByNameGetsTheShims(t *testing.T) {
	linux := target.Target{Platform: "linux", Arch: "x86-64"}
	got := WrapTest(TestWrapOptions{
		UserScript: "cc t.c -lz && ./a.out",
		Package:    "zlib.net@1.3.1",
		Compiler:   true,
		Host:       linux,
		Home:       "/h", Sandbox: "/s", ZpkgDir: "/pkgx",
		ShimDir: "/box.shims",
	})

	guard := strings.Index(got, "if [ ! -e /usr/include/stdlib.h ]")
	closeAt := guard + strings.Index(got[guard:], "\nfi\n")
	path := strings.Index(got, `export PATH="/box.shims":"$PATH"`)
	if path < 0 {
		t.Fatalf("the shim dir is not put on PATH:\n%s", got)
	}
	if path < guard || path > closeAt {
		t.Errorf("PATH is set outside the no-system-libc guard (guard %d, close %d, PATH %d)", guard, closeAt, path)
	}
	// FIRST on PATH: the llvm.org bottle ships its own cc, and a test picking
	// that one is the failure this exists to end.
	if !strings.Contains(got, `export PATH="/box.shims":"$PATH"`) {
		t.Error("the shim dir is appended rather than prepended")
	}
	// The flags live in ZPKB_CC, which is what the shim re-execs — one place,
	// so no invocation gets the sysroot twice.
	for _, want := range []string{`export ZPKB_CC="clang --sysroot=`, `export ZPKB_CXX="clang++ `} {
		if !strings.Contains(got, want) {
			t.Errorf("the shims have nothing to re-exec: %q missing", want)
		}
	}
	// And $CC names the shim rather than carrying the flags again.
	if strings.Contains(got, `export CC="${CC:-cc} --sysroot=`) {
		t.Error("CC still carries the sysroot flags beside the shims, so a test reading $CC gets them twice")
	}
	// Before the user script, or it reaches nothing.
	if path > strings.Index(got, "cc t.c -lz") {
		t.Error("PATH is set after the test runs")
	}
}

// With no shim dir the preamble must still do what it can: put the flags in
// $CC. That is the old behaviour, it reaches the few tests that read $CC, and
// a caller that could not make the symlinks is not a reason to emit nothing.
func TestWithoutAShimDirTheFlagsGoBackIntoCC(t *testing.T) {
	got := WrapTest(TestWrapOptions{
		UserScript: "cc t.c", Package: "zlib.net@1.3.1", Compiler: true,
		Host: target.Target{Platform: "linux", Arch: "x86-64"},
		Home: "/h", Sandbox: "/s", ZpkgDir: "/pkgx",
	})
	if !strings.Contains(got, `export CC="${CC:-cc} --sysroot=`) {
		t.Errorf("no shims and no flags in CC either:\n%s", got)
	}
	if strings.Contains(got, "export PATH=") {
		t.Error("a PATH was exported with no shim dir to put on it")
	}
}

// clang and clang++ must NOT be shimmed: $ZPKB_CC's driver IS clang, so a shim
// of that name would re-exec itself forever. This is the test that keeps
// somebody from "completing" the list.
// clang IS shimmed now, and this test replaces the one that asserted the
// opposite.
//
// The old test said: "$ZPKB_CC starts with clang, so a shim of that name is
// an exec loop" — true, and the reason the two names were left out. The
// cost of leaving them out was then measured: 77 pantry recipes set CC or
// CXX in an `env:` block, mostly to the bare words, and a recipe's env is
// emitted AFTER the sovereign preamble and replaces it whole. autoconf and
// automake fail there with "C compiler cannot create executables".
//
// What makes it safe is not a list but a behaviour: the shim resolves its
// driver while SKIPPING its own directory (cmd/bk resolveDriver). So the
// invariant worth asserting is no longer "clang is absent" — it is that
// every name materialised here is one the dispatcher recognises, and that
// the C++ names route to the C++ driver.
func TestEveryShimMaterialisedIsOneTheDispatcherKnows(t *testing.T) {
	names := compilerShimsFor("x86_64-unknown-linux-gnu", "linux", "x86-64")
	var sawClang bool
	for _, n := range names {
		if n == "clang" {
			sawClang = true
		}
	}
	if !sawClang {
		t.Error("clang is not shimmed, so a recipe naming it still loses the sysroot")
	}
	// The dispatcher's own recogniser lives in cmd/bk and cannot be called
	// from here, so the shared contract is the SUFFIX rule both sides use:
	// a materialised name is a base, or a triple plus "-" plus a base.
	bases := map[string]bool{"cc": true, "gcc": true, "c++": true, "g++": true, "clang": true, "clang++": true}
	for _, n := range names {
		ok := bases[n]
		for b := range bases {
			if strings.HasSuffix(n, "-"+b) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%q is materialised and matches no base the dispatcher knows", n)
		}
	}
}
