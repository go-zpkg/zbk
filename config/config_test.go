package config

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

var errNoHome = errors.New("no home")

// testHash stands in for a build's identity in the tests that only look at the
// SCRATCH paths (Root, Home, Src, Build, Test), none of which carry it. The
// test that does assert the install prefix spells the hash out inline, so that
// the expected path and the argument cannot drift apart through a constant.
const testHash = "abcdefghijklmnop"

func TestZpkgDir(t *testing.T) {
	t.Setenv("ZPKG_DIR", "/opt/pkgx")
	if ZpkgDir() != "/opt/pkgx" {
		t.Errorf("ZpkgDir env = %q", ZpkgDir())
	}
	t.Setenv("ZPKG_DIR", "")
	got := ZpkgDir()
	// ⛔ `.zpkg`, AND IT MUST MATCH bottle.Dir(). This asserted `.pkgx` while
	// bottle/pkgx.go:385 returned `.zpkg`, so the test certified a store root
	// that disagreed with the one the rest of the product used.
	if !strings.HasSuffix(got, ".zpkg") {
		t.Errorf("ZpkgDir default = %q, want a ~/.zpkg suffix", got)
	}
	if strings.HasSuffix(got, ".pkgx") {
		t.Errorf("ZpkgDir default = %q — that is upstream pkgx's store", got)
	}
}

func TestComputeDefaultLayout(t *testing.T) {
	t.Setenv("ZPKG_PANTRY_DIR", "")
	t.Setenv("ZPKG_PANTRY_PATH", "")
	t.Setenv("ZPKG_DIR", "/opt/pkgx")
	t.Setenv("XDG_DATA_HOME", "/data")

	tgt := target.Target{Platform: "windows", Arch: "x86-64", Triple: "x86_64-w64-mingw32"}
	p := Compute("acme.org/tool", "1.2.3", "abcdefghijklmnop", tgt)

	// ⛔ THE INSTALL PREFIX CARRIES THE BUILD'S IDENTITY. It is baked into
	// every binary the build produces, so a prefix naming only the version
	// makes those binaries unable to say which build they were linked
	// against — and leaves a store that cannot hold two builds of one
	// version. The SCRATCH paths below deliberately do not carry it: they are
	// thrown away, and keying them on the hash would only stop a rebuild
	// reusing a fetched source tree.
	if p.Install != filepath.FromSlash("/opt/pkgx/acme.org/tool/v1.2.3-habcdefghijklmnop") {
		t.Errorf("Install = %q", p.Install)
	}
	if p.BuildInstall != p.Install+"+brewing" {
		t.Errorf("BuildInstall = %q", p.BuildInstall)
	}
	// keyed on the TARGET platform+arch
	wantRoot := filepath.FromSlash("/data/brewkit/windows+x86-64/acme.org/tool/v1.2.3")
	if p.Home != wantRoot {
		t.Errorf("Home = %q want %q", p.Home, wantRoot)
	}
	if p.Src != filepath.Join(wantRoot, "src") || p.Build != filepath.Join(wantRoot, "build") || p.Test != filepath.Join(wantRoot, "testbed") {
		t.Errorf("paths = %+v", p)
	}
	if p.TarballDir != filepath.FromSlash("/data/brewkit") {
		t.Errorf("TarballDir = %q", p.TarballDir)
	}

	// a native build for a different target gets a different tree
	q := Compute("acme.org/tool", "1.2.3", "abcdefghijklmnop", target.Target{Platform: "linux", Arch: "aarch64"})
	if q.Home == p.Home {
		t.Error("cross and native builds must not share a tree")
	}
}

// ⛔⛔ A PREFIX WITHOUT AN IDENTITY IS NOT A WEAKER PREFIX, IT IS THE OLD BUG.
// `<store>/<project>/v<version>` is the shape two builds of one version
// overwrote each other in, and it is exactly what Compute would produce from
// an empty hash. Refusing LOUDLY rather than returning a plausible path is
// the point: a caller that does not know the identity has not resolved the
// closure yet, and a silent fallback would put the layout back to two shapes
// with nothing to notice it.
func TestComputeRefusesAPrefixWithNoIdentity(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Compute accepted an empty hash: the prefix would name a version and not a build")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "build identity") {
			t.Errorf("the panic does not say what is missing: %v", r)
		}
	}()
	Compute("acme.org/tool", "1.2.3", "", target.Host())
}

func TestComputePantryCheckoutLayout(t *testing.T) {
	t.Setenv("ZPKG_DIR", "/opt/pkgx")
	t.Setenv("ZPKG_PANTRY_DIR", "/co")
	p := Compute("acme.org/tool", "2.0.0", testHash, target.Host())
	if p.Home != filepath.FromSlash("/co/homes/acme.org__tool-2.0.0") {
		t.Errorf("checkout Home = %q", p.Home)
	}
	if p.Src != filepath.FromSlash("/co/srcs/acme.org__tool-2.0.0") {
		t.Errorf("checkout Src = %q", p.Src)
	}
	if p.Build != filepath.FromSlash("/co/builds/acme.org__tool-2.0.0") {
		t.Errorf("checkout Build = %q", p.Build)
	}
	if p.Test != filepath.FromSlash("/co/testbeds/acme.org__tool-2.0.0") {
		t.Errorf("checkout Test = %q", p.Test)
	}
	if p.TarballDir != filepath.FromSlash("/co/srcs") {
		t.Errorf("checkout TarballDir = %q", p.TarballDir)
	}
	// the older ZPKG_PANTRY_PATH env is honoured too
	t.Setenv("ZPKG_PANTRY_DIR", "")
	t.Setenv("ZPKG_PANTRY_PATH", "/co2")
	if q := Compute("x", "1", testHash, target.Host()); q.Home != filepath.FromSlash("/co2/homes/x-1") {
		t.Errorf("ZPKG_PANTRY_PATH Home = %q", q.Home)
	}
}

func TestNoHomeFallbacks(t *testing.T) {
	orig := userHomeDir
	defer func() { userHomeDir = orig }()
	userHomeDir = func() (string, error) { return "", errNoHome }

	t.Setenv("ZPKG_DIR", "")
	if got := ZpkgDir(); got != ".zpkg" {
		t.Errorf("ZpkgDir no-home = %q", got)
	}
	t.Setenv("XDG_DATA_HOME", "")
	if got := dataHome(); got != filepath.Join(".local", "share") {
		t.Errorf("dataHome no-home = %q", got)
	}
}

func TestDataHomeVariants(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/xdg")
	if dataHome() != "/xdg" {
		t.Errorf("XDG_DATA_HOME = %q", dataHome())
	}
	t.Setenv("XDG_DATA_HOME", "")
	// the runtime wrapper matches the pure fn for the current host
	if dataHome() != dataHomeFor(runtime.GOOS, mustHome(t)) {
		t.Errorf("dataHome != dataHomeFor(host)")
	}
	// both OS branches, pure (darwin uses a space-free Caches path)
	if dataHomeFor("darwin", "/h") != filepath.FromSlash("/h/Library/Caches") {
		t.Errorf("darwin: %q", dataHomeFor("darwin", "/h"))
	}
	if dataHomeFor("linux", "/h") != filepath.FromSlash("/h/.local/share") {
		t.Errorf("linux: %q", dataHomeFor("linux", "/h"))
	}
}

func mustHome(t *testing.T) string {
	t.Helper()
	h, err := userHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestComputeRootCoversEveryBuildDir: Root is what -ffile-prefix-map maps, so
// every directory a build uses must sit under it in BOTH layouts (go-zpkg/bk#387).
func TestComputeRootCoversEveryBuildDir(t *testing.T) {
	tgt := target.Target{Platform: "darwin", Arch: "aarch64", Triple: "aarch64-apple-darwin"}
	for name, setup := range map[string]func(){
		"cache": func() {
			t.Setenv("ZPKG_PANTRY_DIR", "")
			t.Setenv("ZPKG_PANTRY_PATH", "")
			t.Setenv("XDG_DATA_HOME", "/data")
		},
		"pantry": func() { t.Setenv("ZPKG_PANTRY_DIR", "/pantry"); t.Setenv("ZPKG_PANTRY_PATH", "") },
	} {
		setup()
		p := Compute("acme.org/tool", "1.2.3", testHash, tgt)
		if p.Root == "" {
			t.Fatalf("%s: Root empty", name)
		}
		for _, d := range []string{p.Home, p.Src, p.Build, p.Test} {
			if !strings.HasPrefix(d, p.Root+string(filepath.Separator)) {
				t.Errorf("%s: %q is not under Root %q", name, d, p.Root)
			}
		}
	}
}
