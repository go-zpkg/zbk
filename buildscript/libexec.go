package buildscript

import (
	"os"
	"path/filepath"
)

// shims is the set of build-shim helper NAMES bk materialises into the per-build
// libexec dir. Each is created as a symlink to the running bk binary: bk is a
// multi-call ("busybox-style") binary that, when invoked under one of these
// names, runs the matching pure-Go helper — so no shell interpreter is involved.
// Many recipes (ruby-lang.org, gnu.org/stow, gnu.org/autoconf, exiftool.org, …)
// exec these by filename, e.g. `fix-shebangs.ts bin/*`. It is the single place
// to add further brewkit libexec helpers bk chooses to satisfy.
var shims = map[string]struct{}{
	"fix-shebangs.ts":        {},
	"bkpyvenv":               {},
	"python-venv.sh":         {},
	"python-venv.py":         {},
	"python-venv-stubber.sh": {},
}

// seams so WriteLibexec's error branches are testable.
var (
	mkdirAll     = os.MkdirAll
	osExecutable = os.Executable
	osSymlink    = os.Symlink
	osRemove     = os.Remove
)

// WriteLibexec materialises the build-shim helpers into dir, each as a symlink
// to the running bk executable. Point WrapOptions.BrewkitPath at dir so
// wrapper.go prepends it to the build PATH and recipes can exec the shims (e.g.
// `fix-shebangs.ts bin/*`); bk's multi-call dispatch then runs the pure-Go
// helper selected by argv[0]'s basename. If the running executable's path
// cannot be determined the error is returned (never silently fall back to a
// shell script — the failure must stay visible).
// compilerShims are materialised ON TOP of shims in pkgx-libc mode. They matter
// because a recipe may call `cc` or `gcc` DIRECTLY, ignoring $CC — sqlite's
// autosetup does exactly that ("No working C compiler found. Tried cc and
// gcc") — and the bare compiler has none of the sysroot/crt/runtime flags the
// sovereign mode depends on. Named first on PATH, these shims re-exec the real
// driver with them.
//
// `clang` and `clang++` ARE in this list, and used not to be. $ZBK_CC's
// driver is clang and this directory is first on PATH, so a shim of that
// name once found itself; the shim now resolves its driver while skipping
// its own directory (see resolveDriver), which removes the loop.
//
// Leaving them out had a measured cost: 77 pantry recipes set CC or CXX in
// an `env:` block, overwhelmingly to the bare words `clang`, `clang++`,
// `gcc`, `g++`, and a recipe's env is emitted AFTER the sovereign preamble
// and replaces the variable whole. gnu.org/autoconf and gnu.org/automake
// fail exactly there, with "C compiler cannot create executables".
var compilerShims = []string{"cc", "gcc", "c++", "g++", "clang", "clang++"}

// compilerShimsFor is compilerShims plus the TRIPLE-PREFIXED spellings, which
// autoconf reaches for before the bare ones.
//
// libisl's configure looks for `x86_64-pc-linux-gnu-gcc`, finds the bare gcc
// the gnu.org/gcc bottle puts on PATH — without any of the sovereign sysroot,
// crt or runtime flags — and stops at
//
//	checking whether the C compiler works... no
//	configure: error: C compiler cannot create executables
//
// Both spellings are made, and the reason is worth keeping: bk's own
// target.Triple says `x86_64-unknown-linux-gnu`, while autoconf's config.guess
// says `x86_64-pc-linux-gnu`, which is the one the failing build asked for.
// Deriving the name from our constant alone would have shimmed a name nobody
// looks up. They are symlinks; making both costs nothing and guessing wrong
// costs a build.
func compilerShimsFor(triple, platform, arch string) []string {
	names := append([]string{}, compilerShims...)
	seen := map[string]bool{}
	for _, t := range []string{triple, configGuessTriple(platform, arch)} {
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		for _, base := range compilerShims {
			names = append(names, t+"-"+base)
		}
	}
	return names
}

// configGuessTriple is what autoconf's config.guess reports for a platform,
// which is not always what a toolchain calls itself.
func configGuessTriple(platform, arch string) string {
	if platform != "linux" {
		return ""
	}
	switch arch {
	case "x86-64", "amd64", "x86_64":
		return "x86_64-pc-linux-gnu"
	case "aarch64", "arm64":
		return "aarch64-unknown-linux-gnu"
	case "s390x":
		// Measured, not patterned: the two entries above disagree about the
		// vendor field (`pc` against `unknown`), so there is no rule here to
		// extend. Upstream config.guess run on the LinuxONE machine answers
		// s390x-ibm-linux-gnu -- a third vendor again.
		return "s390x-ibm-linux-gnu"
	}
	return ""
}

// WriteLibexecFor is WriteLibexec plus the compiler shims when libcZpkgx is set.
func WriteLibexecFor(dir string, libcZpkgx bool, triple, platform, arch string) error {
	if err := WriteLibexec(dir); err != nil {
		return err
	}
	// `libtool` on darwin, where TWO unrelated programs answer to the name:
	// cctools' libtool merges static libraries, GNU libtool drives compilation.
	// `pkgx +<deps>` prepends the dependency bin dirs to PATH, so any dependency
	// shipping gnu.org/libtool puts the wrong one in front of /usr/bin — and a
	// build that compiled 148 of 2639 objects dies on
	//
	//	libtool:   error: unrecognised option: '-framework'
	//
	// The shim routes an invocation to Apple's only when it carries a flag GNU
	// libtool would refuse, so it can turn an error into a build and nothing
	// else. Written whatever the libc mode: the collision is about PATH, not
	// about a sovereign toolchain.
	if platform == "darwin" {
		// WriteLibexec above has already called osExecutable and returned its
		// error, so there is no failing case left to handle here — a branch no
		// test can reach is a line the coverage gate is right to refuse.
		self, _ := osExecutable()
		link := filepath.Join(dir, "libtool")
		_ = osRemove(link)
		if err := osSymlink(self, link); err != nil {
			return err
		}
	}
	// EVERY target gets the compiler shims. In pkgx-libc and wasip1 modes they
	// carry $ZBK_CC's sovereign flags; in every mode they append
	// -ffile-prefix-map=$ZBK_FILE_PREFIX_MAP, the one setting a recipe's own
	// CFLAGS/CXXFLAGS/CC cannot drop (go-zpkg/bk#387). libcZpkgx no longer gates
	// the shims; it is kept for the callers' signature.
	_ = libcZpkgx
	self, err := osExecutable()
	if err != nil {
		return err
	}
	for _, name := range compilerShimsFor(triple, platform, arch) {
		link := filepath.Join(dir, name)
		_ = osRemove(link)
		if err := osSymlink(self, link); err != nil {
			return err
		}
	}
	return nil
}

func WriteLibexec(dir string) error {
	if err := mkdirAll(dir, 0o755); err != nil {
		return err
	}
	self, err := osExecutable()
	if err != nil {
		return err
	}
	for name := range shims {
		link := filepath.Join(dir, name)
		_ = osRemove(link) // idempotent: os.Symlink fails if the path already exists
		if err := osSymlink(self, link); err != nil {
			return err
		}
	}
	return nil
}
