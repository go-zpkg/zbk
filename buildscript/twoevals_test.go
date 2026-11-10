package buildscript

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zbk/target"
)

// Two `pkgx +…` invocations, not one — and the TOOL one first, because every
// variable pkgx writes prepends, so whatever is evaluated last ends up first on
// the search paths. The link closure must win.
func TestWrapEmitsTwoClosuresToolsFirst(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make",
		Deps:       []string{"unicode.org^71", "freetype.org"},
		ToolDeps:   []string{"nodejs.org", "gnu.org/autoconf"},
		Target:     darwinTgt(), Host: darwinTgt(),
		PkgxBin: "/bin/pkgx",
	})
	tool := strings.Index(s, `"+nodejs.org"`)
	link := strings.Index(s, `"+unicode.org^71"`)
	if tool < 0 || link < 0 {
		t.Fatalf("one of the two closures is missing:\n%s", s)
	}
	if tool > link {
		t.Errorf("the tool closure is evaluated after the link one, so tool paths would come first")
	}

	// They must be SEPARATE invocations: a line carrying both would put the two
	// constraint sets through one resolution, which is the thing being fixed.
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, `"+nodejs.org"`) && strings.Contains(line, `"+unicode.org^71"`) {
			t.Fatalf("both closures in one invocation: %q", line)
		}
	}

	// Each says which closure failed, so an operator is not left guessing.
	if !strings.Contains(s, "zbk: the tool environment failed") {
		t.Error("the tool closure's failure is not named")
	}
	if !strings.Contains(s, "zbk: the dependency environment failed") {
		t.Error("the link closure's failure is not named")
	}
}

// An empty tool set emits nothing at all, so a recipe with no build
// dependencies produces the script it always did.
func TestWrapWithNoToolDepsEmitsOneEval(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"zlib.net"},
		Target: darwinTgt(), Host: darwinTgt(), PkgxBin: "/bin/pkgx",
	})
	if strings.Contains(s, "the tool environment failed") {
		t.Errorf("an empty tool closure still emitted an eval:\n%s", s)
	}
	if !strings.Contains(s, `"+zlib.net"`) {
		t.Errorf("the link closure is missing:\n%s", s)
	}
}

// TestBootstrapTakesTheCompilerFromTheHost.
//
// The base toolchain was only half the injection. bk adds "+llvm.org" to every
// linux build that has no compiler dependency of its own, so --bootstrap
// without this moved the failure one step and no further:
//
//	pkgx: GET https://dist.pkgx.dev/llvm.org/linux/s390x/versions.txt: Not Found
//
// A compiler is a tool that RUNS the build. It belongs on the host side of the
// line --bootstrap draws, exactly like make and m4.
func TestBootstrapTakesTheCompilerFromTheHost(t *testing.T) {
	opts := func(boot bool) WrapOptions {
		return WrapOptions{
			UserScript: "make\n",
			Target:     target.Target{Platform: "linux", Arch: "s390x"},
			Host:       target.Target{Platform: "linux", Arch: "s390x"},
			Bootstrap:  boot,
		}
	}
	ordinary := Wrap(opts(false))
	if !strings.Contains(ordinary, `"+llvm.org"`) {
		t.Fatalf("premise wrong: an ordinary linux build no longer adds llvm.org:\n%s", ordinary)
	}
	boot := Wrap(opts(true))
	if strings.Contains(boot, `"+llvm.org"`) {
		t.Errorf("bootstrap must leave the compiler to the host:\n%s", boot)
	}
}

// And the existing guard still stands on its own: a build that already carries
// a compiler does not get a second one, bootstrap or not. HasCompiler and
// Bootstrap mean different things -- one says the closure HAS a compiler, the
// other says the host does -- and folding them together would lose that.
func TestHasCompilerAndBootstrapAreSeparateReasons(t *testing.T) {
	base := WrapOptions{
		UserScript: "make\n",
		Target:     target.Target{Platform: "linux", Arch: "x86-64"},
		Host:       target.Target{Platform: "linux", Arch: "x86-64"},
	}
	hasComp := base
	hasComp.HasCompiler = true
	if strings.Contains(Wrap(hasComp), `"+llvm.org"`) {
		t.Error("HasCompiler must still suppress the implicit compiler on its own")
	}
}

// TestBootstrapTellsPkgxTheHostHasALibc.
//
// The last of the implicit injections, and the one that stops everything
// rather than one thing: bottle adds gnu.org/glibc to EVERY linux closure, so
// with no glibc bottle `pkgx +anything` fails -- including a bottle the
// factory has just built and published.
//
// The export goes in the SCRIPT, not the process environment, so the reason a
// seed build differs is visible in the artefact that ran it. This test reads
// the script for that reason.
func TestBootstrapTellsPkgxTheHostHasALibc(t *testing.T) {
	opts := func(boot bool) WrapOptions {
		return WrapOptions{
			UserScript: "make\n",
			Target:     target.Target{Platform: "linux", Arch: "s390x"},
			Host:       target.Target{Platform: "linux", Arch: "s390x"},
			Bootstrap:  boot,
		}
	}
	boot := Wrap(opts(true))
	if !strings.Contains(boot, "export ZPKG_IMPLICIT_ROOTS=none") {
		t.Errorf("a seed build must tell pkgx the host supplies the libc:\n%s", boot)
	}
	// And an ordinary build must NOT: a closure assembled without the implicit
	// roots is complete only against the machine that assembled it.
	if strings.Contains(Wrap(opts(false)), "ZPKG_IMPLICIT_ROOTS") {
		t.Error("an ordinary build must keep the implicit roots")
	}
}
