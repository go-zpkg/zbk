// Package config computes the on-disk workspace layout for a build. The build
// tree is keyed on the *target* platform+arch so a cross build (eg. Windows)
// gets its own directories and never collides with a native build of the same
// package.
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-zpkg/zbk/target"
)

// userHomeDir is a seam so tests can exercise the no-home fallback paths.
var userHomeDir = os.UserHomeDir

// Paths is the set of directories a build uses.
type Paths struct {
	// Root is the directory every other build directory lives under (the brewkit
	// cache dir, or the pantry checkout). It is what -ffile-prefix-map maps to
	// /build, so no builder path leaks into a bottle (go-zpkg/bk#387).
	Root         string
	Home         string // a fresh HOME for the build (== bkroot for the default layout)
	Src          string // extracted sources
	Build        string // where the build runs
	Test         string // where tests stage and run
	TarballDir   string // where downloaded source tarballs are cached
	Install      string // final install prefix: $ZPKG_DIR/<project>/v<version>
	BuildInstall string // staging prefix the build writes to: <Install>+brewing
}

// ZpkgDir returns the store prefix ($ZPKG_DIR, else ~/.zpkg).
//
// ⛔⛔ IT MUST AGREE WITH bottle.Dir(), AND FOR A WHILE IT DID NOT. This
// returned `~/.pkgx` long after bottle/pkgx.go:385 moved the store to
// `~/.zpkg`, so one product had two functions computing the store root and
// they disagreed — zbk staged and looked in upstream pkgx's directory while
// everything built on bottle used ours. The duplication is the defect; this
// is the cheap half of the fix and the two should become one call.
func ZpkgDir() string {
	if d := os.Getenv("ZPKG_DIR"); d != "" {
		return d
	}
	home, err := userHomeDir()
	if err != nil {
		return ".zpkg"
	}
	return filepath.Join(home, ".zpkg")
}

// dataHome is the XDG data home ($XDG_DATA_HOME, else ~/.local/share; on macOS
// ~/Library/Application Support), matching where brewkit stores its build tree.
func dataHome() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return d
	}
	home, err := userHomeDir()
	if err != nil {
		return filepath.Join(".local", "share")
	}
	return dataHomeFor(runtime.GOOS, home)
}

// dataHomeFor is the pure, testable OS split of dataHome. On darwin it uses
// ~/Library/Caches rather than "Application Support": the build tree lives here
// and that path has NO space — autotools/libtool choke on spaces in build paths
// even when quoted, and "Application Support" would poison every macOS build.
func dataHomeFor(goos, home string) string {
	if goos == "darwin" {
		return filepath.Join(home, "Library", "Caches")
	}
	return filepath.Join(home, ".local", "share")
}

// Compute lays out the build directories for project@version built for tgt.
//
// When ZPKG_PANTRY_DIR (or the older ZPKG_PANTRY_PATH) is set, the workspace is
// rooted under that checkout (homes/srcs/builds/testbeds), matching brewkit's
// in-pantry layout; otherwise it lives under the XDG data home, keyed on the
// target platform+arch.
// ⛔⛔ `hash` IS THE BUILD'S IDENTITY AND IT GOES IN THE INSTALL PREFIX. The
// prefix is baked into every binary the build produces — an `@rpath`-relative
// reference like `@rpath/zlib.net/v1.3.2/lib/libz.1.dylib`, read out of a
// real published bottle — so a prefix that names only the version produces
// binaries that cannot say WHICH build they were linked against, and a store
// that cannot hold two builds of one version.
//
// With the hash in it the bottle stays relocatable AND names itself, which is
// the combination Nix gives up (its paths are absolute) and Spack gives up
// (its paths are not designed to move). See go-zpkg/zbk#410.
//
// An empty hash is not accepted: a caller that does not know the identity
// has not resolved the closure yet, and the prefix must not be chosen before
// it has.
func Compute(project, version, hash string, tgt target.Target) Paths {
	if hash == "" {
		panic("config: Compute with no build identity — the prefix would not name which build it is")
	}
	install := filepath.Join(ZpkgDir(), filepath.FromSlash(project), "v"+version+"-h"+hash)
	p := Paths{
		Install:      install,
		BuildInstall: install + "+brewing",
	}

	if checkout := pantryCheckout(); checkout != "" {
		p.Root = checkout
		slug := strings.ReplaceAll(project, "/", "__")
		spec := slug + "-" + version
		p.Home = filepath.Join(checkout, "homes", spec)
		p.Src = filepath.Join(checkout, "srcs", spec)
		p.Build = filepath.Join(checkout, "builds", spec)
		p.Test = filepath.Join(checkout, "testbeds", spec)
		p.TarballDir = filepath.Join(checkout, "srcs")
		return p
	}

	dh := filepath.Join(dataHome(), "brewkit")
	root := filepath.Join(dh, tgt.Platform+"+"+tgt.Arch, filepath.FromSlash(project), "v"+version)
	p.Root = dh
	p.Home = root
	p.Src = filepath.Join(root, "src")
	p.Build = filepath.Join(root, "build")
	p.Test = filepath.Join(root, "testbed")
	p.TarballDir = dh
	return p
}

func pantryCheckout() string {
	if d := os.Getenv("ZPKG_PANTRY_DIR"); d != "" {
		return d
	}
	return os.Getenv("ZPKG_PANTRY_PATH")
}
