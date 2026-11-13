package buildscript

import (
	"strings"
	"testing"

	"github.com/go-zpkg/zpkb/target"
)

func linuxTgt() target.Target  { return target.Target{Platform: "linux", Arch: "x86-64"} }
func darwinTgt() target.Target { return target.Target{Platform: "darwin", Arch: "aarch64"} }
func winTgt() target.Target    { return target.Target{Platform: "windows", Arch: "x86-64"} }

func TestWrapLinux(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "./configure\nmake install\n",
		Deps:       []string{"openssl.org@1.1", "zlib.net"},
		Target:     linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
		BrewkitPath: "/bk/libexec", ZpkgxBin: "/opt/pkgx/bin/pkgx", BashPath: "/opt/bash",
	})
	wants := []string{
		"#!/opt/bash\n",
		"set -eo pipefail",
		`__bk_deps_env="$(CLICOLOR_FORCE=1 /opt/pkgx/bin/pkgx "+openssl.org@1.1" "+zlib.net" "+llvm.org")" || {`,
		`export PATH="/bk/libexec:$PATH"`,
		`export CMAKE_PREFIX_PATH="/opt/pkgx${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"`,
		`export ZPKGX="/opt/pkgx/bin/pkgx"`,
		`export HOME="/bk/home"`,
		`export SRCROOT="/bk/build"`,
		`export TMPDIR="$HOME/tmp"; mkdir -p "$TMPDIR"`,
		"export FORCE_UNSAFE_CONFIGURE=1",
		`export LDFLAGS="-Wl,-rpath,/opt/pkgx $LDFLAGS"`,
		`export CFLAGS="-fPIC -Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion $CFLAGS"`,
		`export CXXFLAGS="-fPIC $CXXFLAGS"`,
		"env -u GH_TOKEN -u GITHUB_TOKEN",
		`cd "/bk/build"`,
		"./configure\nmake install",
	}
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
	// linux gets an rpath slot (relocated $ORIGIN-relative by fixup) but no
	// darwin-only MACOSX_DEPLOYMENT_TARGET.
	if strings.Contains(s, "MACOSX_DEPLOYMENT_TARGET") {
		t.Error("linux script has darwin flags")
	}
}

func TestWrapLinuxArm64Flags(t *testing.T) {
	// linux/aarch64: the C23-relaxation CFLAGS apply, but without -fPIC (default
	// on arm64) and without the x86-64 -pie LDFLAGS / -fPIC CXXFLAGS.
	s := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"x"},
		Target:  target.Target{Platform: "linux", Arch: "aarch64"},
		Host:    target.Target{Platform: "linux", Arch: "aarch64"},
		ZpkgDir: "/opt/pkgx",
	})
	if !strings.Contains(s, `export CFLAGS="-Wno-implicit-function-declaration -Wno-implicit-int -Wno-int-conversion $CFLAGS"`) {
		t.Errorf("arm64 CFLAGS wrong:\n%s", s)
	}
	// aarch64 links PIE by default: rpath slot, but no -pie / -fPIC / CXXFLAGS.
	if !strings.Contains(s, `export LDFLAGS="-Wl,-rpath,/opt/pkgx $LDFLAGS"`) {
		t.Errorf("arm64 LDFLAGS should carry the rpath slot only:\n%s", s)
	}
	if strings.Contains(s, "-fPIC") || strings.Contains(s, "-pie") || strings.Contains(s, "CXXFLAGS") {
		t.Errorf("arm64 got x86-64-only flags:\n%s", s)
	}
}

func TestWrapDarwinWithBinutils(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"x"}, Target: darwinTgt(), Host: darwinTgt(),
		ZpkgDir: "/opt/pkgx", HasBinutils: true,
	})
	// darwin host => NO default llvm.org appended
	if strings.Contains(s, "+llvm.org") {
		t.Error("darwin host should not add default llvm.org")
	}
	for _, w := range []string{
		`export LDFLAGS="-Wl,-rpath,/opt/pkgx -Wl,-headerpad_max_install_names -Wno-unused-command-line-argument $LDFLAGS"`,
		"export MACOSX_DEPLOYMENT_TARGET=11.0",
		"export AR=/usr/bin/ar",
		"export RANLIB=/usr/bin/ranlib",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q", w)
		}
	}
	// no -pie/-fPIC on darwin
	if strings.Contains(s, "-pie") || strings.Contains(s, "-fPIC") {
		t.Error("darwin got linux flags")
	}
}

func TestWrapWindowsCross(t *testing.T) {
	// windows target on a linux host: no default llvm.org, no FLAGS; TMPDIR is
	// host-based (linux) so TMPDIR not TMP.
	s := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"llvm.org/mingw-w64"},
		Target: winTgt(), Host: linuxTgt(), Home: "/h", SrcRoot: "/s",
	})
	if strings.Contains(s, `"+llvm.org"`) {
		t.Error("windows target must not add default llvm.org")
	}
	if strings.Contains(s, "LDFLAGS") || strings.Contains(s, "-pie") || strings.Contains(s, "rpath") {
		t.Errorf("windows target should have no FLAGS:\n%s", s)
	}
	if !strings.Contains(s, `export TMPDIR="$HOME/tmp"`) {
		t.Error("linux host => TMPDIR")
	}
}

func TestWrapWindowsHostTmp(t *testing.T) {
	s := Wrap(WrapOptions{UserScript: "x", Host: winTgt(), Target: winTgt()})
	if !strings.Contains(s, `export TMP="$HOME/tmp"; export TEMP="$HOME/tmp"`) {
		t.Errorf("windows host => TMP/TEMP: %s", s)
	}
}

func TestWrapHasCompilerAndDefaults(t *testing.T) {
	// HasCompiler suppresses the default llvm.org even on a linux host
	s := Wrap(WrapOptions{UserScript: "x", Deps: []string{"gnu.org/gcc"}, Target: linuxTgt(), Host: linuxTgt(), HasCompiler: true})
	if strings.Contains(s, "+llvm.org") {
		t.Error("HasCompiler should suppress default llvm.org")
	}
	// defaults: no deps => no eval block; default bash + pkgx
	s2 := Wrap(WrapOptions{UserScript: "x", Target: darwinTgt(), Host: darwinTgt()})
	if strings.Contains(s2, "__bk_deps_env=") {
		t.Error("no deps + darwin host => no eval block")
	}
	if !strings.HasPrefix(s2, "#!/bin/bash\n") {
		t.Error("default bash shebang")
	}
	// no-deps linux still gets the llvm.org default => an eval block appears
	s3 := Wrap(WrapOptions{UserScript: "x", Target: linuxTgt(), Host: linuxTgt()})
	if !strings.Contains(s3, `__bk_deps_env="$(CLICOLOR_FORCE=1 zpkgx "+llvm.org")" || {`) {
		t.Errorf("no-dep linux should still eval default llvm.org via `zpkgx`: %s", s3)
	}
}

func linuxArm64Tgt() target.Target { return target.Target{Platform: "linux", Arch: "aarch64"} }

func TestWrapLibcZpkgxLinuxX86(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make install\n",
		Deps:       []string{"zlib.net"},
		Target:     linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
		ZpkgxBin: "/opt/pkgx/bin/pkgx", LibcZpkgx: true,
	})
	wants := []string{
		// glibc + kernel-headers + binutils + libcxx bottles join the eval.
		`"+zlib.net" "+llvm.org" "+gnu.org/glibc" "+kernel.org/linux-headers" "+gnu.org/binutils" "+libcxx.llvm.org"`,
		// Build-time resolution of each bottle prefix. bkresolve DROPS an
		// unmatched pattern instead of letting the shell pass it through literally:
		// a literal `v[0-9]*` in the flags reaches the linker and breaks the very
		// first configure probe.
		`bkresolve() { set +f; for d in $1; do case "$d" in *'*'*|*'['*) continue;; esac; printf '%s\n' "$d"; done | sort -V | tail -n1; }`,
		`export ZPKB_GLIBC_PREFIX="$(bkresolve "$ZPKG_DIR/gnu.org/glibc/v[0-9]*")"`,
		`export ZPKB_LIBCXX_PREFIX="$(bkresolve "$ZPKG_DIR/libcxx.llvm.org/v[0-9]*")"`,
		// C: glibc sysroot + compiler-rt, no unwinder (exception-free C).
		`export CFLAGS="-fPIC --sysroot="$ZPKB_GLIBC_PREFIX" -isystem "${ZPKB_GLIBC_PREFIX}include" -isystem "${ZPKB_KHDR_PREFIX}include" -B "$ZPKB_GLIBC_LIB" -L"$ZPKB_GLIBC_LIB"${ZPKB_LIBGCC:+ -L"$ZPKB_LIBGCC"} --rtlib=compiler-rt -fuse-ld=lld -Wno-unused-command-line-argument --unwindlib=none -Wno-implicit-function-declaration`,
		// C++: libc++ headers FIRST (before glibc's), then sysroot + libunwind.
		`export CXXFLAGS="${ZPKB_LIBCXX_PREFIX:+-stdlib=libc++ -isystem "${ZPKB_LIBCXX_PREFIX}include/c++/v1"} --sysroot="$ZPKB_GLIBC_PREFIX" -isystem "${ZPKB_GLIBC_PREFIX}include" -isystem "${ZPKB_KHDR_PREFIX}include" -B "$ZPKB_GLIBC_LIB" -L"$ZPKB_GLIBC_LIB"${ZPKB_LIBGCC:+ -L"$ZPKB_LIBGCC"} --rtlib=compiler-rt -fuse-ld=lld -Wno-unused-command-line-argument ${ZPKB_LIBCXX_PREFIX:+--unwindlib=libunwind} -fPIC`,
		// The compiler is pinned to the pkgx clang AND carries the whole driver
		// configuration, because libtool builds its own command lines from $CC
		// and ignores CFLAGS/LDFLAGS.
		`export CC="${CC:-clang --sysroot="$ZPKB_GLIBC_PREFIX"`,
		`export CXX="${CXX:-clang++ ${ZPKB_LIBCXX_PREFIX:+-stdlib=libc++`,
		`--rtlib=compiler-rt -fuse-ld=lld -Wno-unused-command-line-argument --unwindlib=none}"`,
		// PT_INTERP = the bottle's x86-64 loader; libc + libc++/libunwind lib search paths; DT_RPATH.
		`-Wl,--dynamic-linker="${ZPKB_GLIBC_LIB}ld-linux-x86-64.so.2" -Wl,-rpath,"$ZPKB_GLIBC_LIB" ${ZPKB_LIBCXX_PREFIX:+-L"${ZPKB_LIBCXX_PREFIX}lib" -Wl,-rpath,"${ZPKB_LIBCXX_PREFIX}lib"} -Wl,--disable-new-dtags -Wl,--undefined-version`,
	}
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
	// The C23 relax + own-lib rpath still apply alongside the glibc targeting.
	if !strings.Contains(s, "-Wno-implicit-function-declaration") || !strings.Contains(s, "-Wl,-rpath,/opt/pkgx") {
		t.Errorf("base linux flags dropped in pkgx-libc mode:\n%s", s)
	}
}

// The freestanding driver is the escape hatch a kernel needs: the pinned pkgx
// clang carrying NO libc include directory. What matters is not the string but
// the property — a build that supplies its own headers must be able to get
// glibc's off its search path, and -nostdinc cannot remove an -isystem the
// driver prepends. Asserted as "no -isystem anywhere in the value" so that a
// later flag added to the hosted driver cannot leak in unnoticed.
func TestWrapLibcZpkgxFreestandingDriver(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make\n", Target: linuxArm64Tgt(), Host: linuxArm64Tgt(),
		ZpkgDir: "/opt/pkgx", LibcZpkgx: true,
	})
	const want = `export ZPKB_CC_FREESTANDING="clang"`
	if !strings.Contains(s, want) {
		t.Fatalf("missing %q in:\n%s", want, s)
	}
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "export ZPKB_CC_FREESTANDING=") {
			continue
		}
		if strings.Contains(line, "-isystem") || strings.Contains(line, "--sysroot") {
			t.Errorf("freestanding driver carries a libc path: %s", line)
		}
	}
}

// Outside pkgx-libc mode nothing injects a libc include directory, so there is
// nothing to escape and no variable to offer.
func TestWrapFreestandingDriverOnlyInLibcZpkgx(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make\n", Target: linuxArm64Tgt(), Host: linuxArm64Tgt(),
		ZpkgDir: "/opt/pkgx",
	})
	if strings.Contains(s, "ZPKB_CC_FREESTANDING") {
		t.Errorf("freestanding driver exported outside pkgx-libc mode:\n%s", s)
	}
}

func TestWrapLibcZpkgxArm64Loader(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make\n", Target: linuxArm64Tgt(), Host: linuxArm64Tgt(),
		ZpkgDir: "/opt/pkgx", LibcZpkgx: true,
	})
	if !strings.Contains(s, `ld-linux-aarch64.so.1`) {
		t.Errorf("arm64 loader wrong:\n%s", s)
	}
	if strings.Contains(s, "ld-linux-x86-64") || strings.Contains(s, "-fPIC") {
		t.Errorf("arm64 script leaked x86-64 flags:\n%s", s)
	}
	// arm64 CXXFLAGS leads with libc++ then the glibc sysroot (non-fPIC branch).
	if !strings.Contains(s, `export CXXFLAGS="${ZPKB_LIBCXX_PREFIX:+-stdlib=libc++ -isystem "${ZPKB_LIBCXX_PREFIX}include/c++/v1"} --sysroot="$ZPKB_GLIBC_PREFIX"`) {
		t.Errorf("arm64 CXXFLAGS missing libc++/sysroot:\n%s", s)
	}
}

func TestWrapLibcZpkgxNonLinuxIgnored(t *testing.T) {
	// LibcZpkgx only affects linux: darwin gets neither the glibc dep nor flags.
	s := Wrap(WrapOptions{
		UserScript: "make\n", Target: darwinTgt(), Host: linuxTgt(), LibcZpkgx: true,
	})
	if strings.Contains(s, "gnu.org/glibc") || strings.Contains(s, "ZPKB_GLIBC") || strings.Contains(s, "--dynamic-linker") {
		t.Errorf("darwin target must ignore LibcZpkgx:\n%s", s)
	}
}

func TestGlibcLoader(t *testing.T) {
	for _, c := range []struct{ arch, want string }{
		{"x86-64", "ld-linux-x86-64.so.2"},
		{"aarch64", "ld-linux-aarch64.so.1"},
		{"arm64", "ld-linux-aarch64.so.1"},
		// Not ld-linux-s390x.so.*: measured on the machine.
		{"s390x", "ld64.so.1"},
	} {
		got, ok := glibcLoader(c.arch)
		if !ok || got != c.want {
			t.Errorf("glibcLoader(%q)=%q,%v want %q,true", c.arch, got, ok, c.want)
		}
	}
	// An arch nobody has measured must REFUSE rather than hand back x86-64's
	// loader, which is what this function used to do for everything it did not
	// recognise.
	if got, ok := glibcLoader("riscv64"); ok {
		t.Errorf("glibcLoader(riscv64) = %q, true; want an admission that it does not know", got)
	}
}

// TestWrapLibcZpkgxGlibcPin: -glibc pins the exact glibc version in the eval.
func TestWrapLibcZpkgxGlibcPin(t *testing.T) {
	for _, in := range []string{"2.27.0", "=2.27.0"} {
		s := Wrap(WrapOptions{
			UserScript: "make install\n",
			Target:     linuxTgt(), Host: linuxTgt(),
			Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
			ZpkgxBin: "/opt/pkgx/bin/pkgx", LibcZpkgx: true, Glibc: in,
		})
		// `@<version>`, no operator: pkgx REJECTS `@=2.27.0` ("invalid semver")
		// and that error aborts the ENTIRE env eval, so nothing installs and the
		// build silently falls back to the container's toolchain.
		if !strings.Contains(s, `"+gnu.org/glibc@2.27.0"`) {
			t.Errorf("glibc=%q: missing pinned +gnu.org/glibc@2.27.0 in:\n%s", in, s)
		}
		if strings.Contains(s, "glibc@=") {
			t.Errorf("glibc=%q: pkgx rejects the @= form:\n%s", in, s)
		}
		if strings.Contains(s, `"+gnu.org/glibc" `) {
			t.Errorf("glibc=%q: unpinned glibc spec present", in)
		}
	}
	// no pin -> unversioned (newest)
	s := Wrap(WrapOptions{
		Target: linuxTgt(), Host: linuxTgt(), Home: "/h", SrcRoot: "/b",
		ZpkgDir: "/opt/pkgx", ZpkgxBin: "/opt/pkgx/bin/pkgx", LibcZpkgx: true,
	})
	if !strings.Contains(s, `"+gnu.org/glibc"`) || strings.Contains(s, "glibc@") {
		t.Errorf("no-pin should use unversioned glibc:\n%s", s)
	}
}

// TestWrapDepEnvIsFatal: a failed dependency environment must STOP the build.
// `eval "$(pkgx +…)"` swallows it — the substitution is empty, eval succeeds,
// and the build runs on with no deps, failing later with something unrelated.
func TestWrapDepEnvIsFatal(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make", Deps: []string{"zlib.net"},
		Target: linuxTgt(), Host: linuxTgt(), ZpkgxBin: "/opt/pkgx/bin/pkgx",
	})
	for _, w := range []string{
		`__bk_deps_env="$(CLICOLOR_FORCE=1 /opt/pkgx/bin/pkgx "+zlib.net" "+llvm.org")" || {`,
		`echo "zpkb: the dependency environment failed`,
		"  exit 1\n}",
		`eval "$__bk_deps_env"`,
		"unset __bk_deps_env",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
	// the guard sits INSIDE the export-all window, so the eval'd assignments
	// are still exported to the build
	iSetA := strings.Index(s, "set -a")
	iEval := strings.Index(s, `eval "$__bk_deps_env"`)
	iSetPlusA := strings.Index(s, "set +a")
	if !(iSetA < iEval && iEval < iSetPlusA) {
		t.Fatalf("the eval must stay between set -a and set +a:\n%s", s)
	}
}

// TestWrapLibcZpkgxUndefinedVersion: lld 17 defaults to --no-undefined-version,
// where GNU ld — which every recipe is written against — merely warns. Without
// restoring the permissive behaviour, a version script that names a symbol the
// build did not produce is fatal: gnu.org/gettext dies on
// 'iconv_ostream_create' because libtextstyle's script exports symbols its
// configure left out.
func TestWrapLibcZpkgxUndefinedVersion(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make", Target: target.Target{Platform: "linux", Arch: "aarch64"},
		Host: target.Target{Platform: "linux", Arch: "aarch64"}, LibcZpkgx: true,
	})
	if !strings.Contains(s, "-Wl,--undefined-version") {
		t.Errorf("the lld strict default must be relaxed:\n%s", s)
	}
	// and only in the pkgx-libc mode, which is the one that uses lld
	plain := Wrap(WrapOptions{
		UserScript: "make", Target: target.Target{Platform: "linux", Arch: "aarch64"},
		Host: target.Target{Platform: "linux", Arch: "aarch64"},
	})
	if strings.Contains(plain, "--undefined-version") {
		t.Error("a system-libc build uses the system linker; leave its defaults alone")
	}
}

// TestIncompatibleFunctionPointerFlagIsClangOnly pins the compiler the flag
// belongs to. gcc has no -Wincompatible-function-pointer-types (it spells the
// check -Wincompatible-pointer-types), and an unknown warning name inside
// -Wno-error= is a HARD ERROR there, not the silent no-op an unknown -Wno-
// gets. Emitting it outside sovereign mode broke kernel.org/libcap in CI —
// where bk compiles with the runner's gcc — while the clang-based sovereign
// builder sailed through, which is exactly the shape of bug a test like this
// exists to stop.
func TestIncompatibleFunctionPointerFlagIsClangOnly(t *testing.T) {
	const flag = "-Wno-error=incompatible-function-pointer-types"

	gcc := Wrap(WrapOptions{
		UserScript: "make install\n",
		Target:     linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
		ZpkgxBin: "/opt/pkgx/bin/pkgx",
	})
	if strings.Contains(gcc, flag) {
		t.Errorf("the clang-only flag reached a gcc build:\n%s", gcc)
	}
	// The C23 demotions gcc DOES understand must still be there — this is about
	// one flag, not about giving up on building old C.
	for _, want := range []string{"-Wno-implicit-function-declaration", "-Wno-implicit-int", "-Wno-int-conversion"} {
		if !strings.Contains(gcc, want) {
			t.Errorf("gcc build lost %s:\n%s", want, gcc)
		}
	}

	clang := Wrap(WrapOptions{
		UserScript: "make install\n",
		Target:     linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
		ZpkgxBin: "/opt/pkgx/bin/pkgx", LibcZpkgx: true,
	})
	if !strings.Contains(clang, flag) {
		t.Errorf("sovereign (clang) build lost the flag gnu.org/gettext needs:\n%s", clang)
	}
}

// TestSovereignCarriesLibgccInTheDriver: rustc does not go through $CC — it
// invokes `cc` itself as the linker driver — and it emits a bare `-lgcc` of its
// own on *-linux-gnu, which --rtlib=compiler-rt does not remove. A tree with no
// distribution has no libgcc on any default search path:
//
//	ld.lld: error: unable to find library -lgcc
//
// which is every Rust recipe, not one: it surfaced on the build scripts of
// getrandom and zerocopy, crates nobody named.
//
// The path travels in the DRIVER flags, not in RUSTFLAGS. RUSTFLAGS was tried
// first and is the wrong vehicle: a recipe may set `env: RUSTFLAGS:` and a
// recipe's env is emitted after this preamble, overwriting it whole —
// crates.io/wasm-pack and crates.io/spider_cli both do, and both went on
// failing on -lgcc while recipes that set no RUSTFLAGS built fine. $ZPKB_CC is
// not a variable a recipe sets, and `cc` on PATH is bk's shim, which re-execs
// it.
func TestSovereignCarriesLibgccInTheDriver(t *testing.T) {
	opts := WrapOptions{
		UserScript: "make", Deps: []string{"x"},
		Target: linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
	}
	sovereign := opts
	sovereign.LibcZpkgx = true
	got := Wrap(sovereign)
	// Resolved from the tree, never spelled out: both the triple and the
	// version in lib/gcc/<triple>/<version> move with the bottle.
	if !strings.Contains(got, `ZPKB_LIBGCC="$(bkresolve`) {
		t.Error("the libgcc path must be resolved, not spelled out")
	}
	// Guarded, so an absent gcc bottle contributes nothing rather than a glob.
	if !strings.Contains(got, `${ZPKB_LIBGCC:+ -L"$ZPKB_LIBGCC"}`) {
		t.Error("the libgcc search path must be guarded")
	}
	// It has to be resolved BEFORE the driver flags that interpolate it, or the
	// exports read an empty variable and the whole point is lost.
	if strings.Index(got, `ZPKB_LIBGCC="$(bkresolve`) > strings.Index(got, `export ZPKB_CC=`) {
		t.Error("ZPKB_LIBGCC is resolved after the driver that uses it")
	}
	// In every driver a build can reach: $CC/$CXX for recipes that honour them,
	// $ZPKB_CC/$ZPKB_CXX for the shims a recipe reaches by calling `cc` or `gcc` —
	// which is the path rustc takes.
	for _, v := range []string{"export CC=", "export CXX=", "export ZPKB_CC=", "export ZPKB_CXX="} {
		line := got[strings.Index(got, v):]
		line = line[:strings.Index(line, "\n")]
		if !strings.Contains(line, `-L"$ZPKB_LIBGCC"`) {
			t.Errorf("%s does not carry the libgcc search path:\n%s", v, line)
		}
	}
	// RUSTFLAGS is no longer the vehicle, and must not come back as one: a
	// recipe overwrites it.
	if strings.Contains(got, "RUSTFLAGS=") {
		t.Error("the sovereign preamble must not set RUSTFLAGS — a recipe overwrites it")
	}
	// Not in the ordinary mode, where the flags stay compiler-neutral.
	if strings.Contains(Wrap(opts), "ZPKB_LIBGCC") {
		t.Error("the libgcc path leaked into the non-sovereign mode")
	}
}

// TestDarwinGivesRustcTheRpath: rustc does not read LDFLAGS — it invokes the
// linker itself — so the -Wl,-rpath bk puts there never reaches a Rust link.
//
// On linux that is survivable because `cc` on PATH is bk's shim. On darwin
// there is no shim, and a Rust package linking a pkgx dylib came out with NO
// LC_RPATH at all:
//
//	dyld: Library not loaded: @rpath/openssl.org/v3.6.4/lib/libssl.3.dylib
//	  Reason: no LC_RPATH's found
//
// which is a binary that cannot start outside the tree that built it —
// published, signed and attested.
func TestDarwinGivesRustcTheRpath(t *testing.T) {
	darwin := Wrap(WrapOptions{
		UserScript: "make", Target: target.Target{Platform: "darwin", Arch: "aarch64"},
		Host: target.Target{Platform: "darwin", Arch: "aarch64"},
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
		Install: "/opt/pkgx/acme.org/foo/v1.2.3",
	})
	// The SAME list LDFLAGS gets, relative entries included. With only the
	// absolute one, a Rust package installs with no rpath reaching $ZPKG_DIR,
	// and fixup then correctly refuses to rewrite its install names into
	// @rpath/… — leaving the bottle exactly as unrelocatable as before, while
	// building, publishing and running perfectly on the machine that made it.
	want := `export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-rpath,@loader_path/../../../.. -C link-arg=-Wl,-rpath,@loader_path/../../../../.. -C link-arg=-Wl,-rpath,@loader_path/../../../../../.. -C link-arg=-Wl,-rpath,@loader_path/../../../../../../.. -C link-arg=-Wl,-rpath,@loader_path/../../../../../../../.. -C link-arg=-Wl,-rpath,/opt/pkgx -C link-arg=-Wl,-headerpad_max_install_names"`
	if !strings.Contains(darwin, want) {
		t.Errorf("darwin must hand rustc every rpath, not just the absolute one:\nwant %s\ngot:\n%s", want, darwin)
	}
	// Composed, never replacing: a recipe's env is emitted after this preamble,
	// and taking the variable away is how the -lgcc fix was lost once already.
	if !strings.Contains(darwin, `RUSTFLAGS="${RUSTFLAGS:-}`) {
		t.Error("RUSTFLAGS must compose with what the recipe sets")
	}
	// linux keeps reaching rustc through the cc shim, so it needs nothing here;
	// adding it there would be a second, competing channel.
	linux := Wrap(WrapOptions{
		UserScript: "make", Target: linuxTgt(), Host: linuxTgt(),
		Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
	})
	if strings.Contains(linux, "RUSTFLAGS") {
		t.Errorf("linux must not set RUSTFLAGS — the shim already carries it:\n%s", linux)
	}
	// And windows gets no rpath of any kind: a PE has none.
	win := Wrap(WrapOptions{
		UserScript: "make", Target: target.Target{Platform: "windows", Arch: "x86-64"},
		Host: linuxTgt(), Home: "/bk/home", SrcRoot: "/bk/build", ZpkgDir: "/opt/pkgx",
	})
	if strings.Contains(win, "RUSTFLAGS") || strings.Contains(win, "-rpath") {
		t.Errorf("windows must get no rpath:\n%s", win)
	}
}

// A darwin link gets a RELATIVE rpath at the depth this package installs at,
// before the absolute one. Unlike ELF's RUNPATH, an LC_RPATH cannot be
// lengthened at fixup time — the string sits in a fixed-size load command, and
// "@loader_path/../../../.." is longer than the "/Users/runner/.pkgx" it would
// replace. So it is linked in from the start or it is never there at all.
func TestDarwinLinksRelativeRpaths(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make install", Target: darwinTgt(),
		ZpkgDir: "/opt/pkgx", Install: "/opt/pkgx/acme.org/foo/v1.2.3",
	})
	want := `export LDFLAGS="-Wl,-rpath,@loader_path/../../../.. -Wl,-rpath,@loader_path/../../../../.. -Wl,-rpath,@loader_path/../../../../../.. -Wl,-rpath,@loader_path/../../../../../../.. -Wl,-rpath,@loader_path/../../../../../../../.. -Wl,-rpath,/opt/pkgx -Wl,-headerpad_max_install_names -Wno-unused-command-line-argument $LDFLAGS"`
	if !strings.Contains(s, want) {
		t.Errorf("darwin LDFLAGS:\nwant %s\nin:\n%s", want, s)
	}
}

// Depths are counted, not assumed: a one-segment project sits one level
// shallower, and a hand-written `bk fixup` with no install prefix gets the
// absolute rpath alone rather than a relative one aimed at nothing.
func TestDarwinRpathDepths(t *testing.T) {
	for _, tc := range []struct {
		name, zpkgDir, install string
		want                   []string
	}{
		// Five depths, not two: bin/ and lib/ are the first two, and the rest are
		// for a loadable module nested under lib/ — libX11 puts input methods at
		// lib/X11/locale/common/, four levels down, and with only two depths its
		// ONLY rpath reaching a sibling package was the absolute one.
		{"two-segment project", "/opt/pkgx", "/opt/pkgx/acme.org/foo/v1.2.3",
			[]string{
				"-Wl,-rpath,@loader_path/../../../..",
				"-Wl,-rpath,@loader_path/../../../../..",
				"-Wl,-rpath,@loader_path/../../../../../..",
				"-Wl,-rpath,@loader_path/../../../../../../..",
				"-Wl,-rpath,@loader_path/../../../../../../../..",
				"-Wl,-rpath,/opt/pkgx"}},
		{"one-segment project", "/opt/pkgx", "/opt/pkgx/acme.org/v1.2.3",
			[]string{
				"-Wl,-rpath,@loader_path/../../..",
				"-Wl,-rpath,@loader_path/../../../..",
				"-Wl,-rpath,@loader_path/../../../../..",
				"-Wl,-rpath,@loader_path/../../../../../..",
				"-Wl,-rpath,@loader_path/../../../../../../..",
				"-Wl,-rpath,/opt/pkgx"}},
		{"no install prefix", "/opt/pkgx", "", []string{"-Wl,-rpath,/opt/pkgx"}},
		{"installed outside $ZPKG_DIR", "/opt/pkgx", "/elsewhere/foo/v1", []string{"-Wl,-rpath,/opt/pkgx"}},
		{"installed AT $ZPKG_DIR", "/opt/pkgx", "/opt/pkgx", []string{"-Wl,-rpath,/opt/pkgx"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := darwinRpaths(tc.zpkgDir, tc.install)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("darwinRpaths = %q, want %q", got, tc.want)
			}
		})
	}
}

// GNU grep's configure refuses OUTRIGHT if GREP or EGREP is set — not if it is
// set to something bad, if it is set at all:
//
//	if test -n "$GREP" || test -n "$EGREP"; then
//	  as_fn_error $? "no working 'grep' found
//
// The message names a missing tool; the condition is a present variable. So the
// factory could not build gnu.org/grep at all, and the error sent three
// investigations after the grep on PATH, which was fine throughout.
func TestToolVarsSkipWhatTheProjectProvides(t *testing.T) {
	for _, tc := range []struct {
		project string
		absent  []string
		present []string
	}{
		{"gnu.org/grep", []string{"GREP=", "EGREP=", "FGREP="}, []string{"SED="}},
		{"gnu.org/sed", []string{"SED="}, []string{"GREP=", "EGREP=", "FGREP="}},
		{"acme.org/thing", nil, []string{"SED=", "GREP=", "EGREP=", "FGREP="}},
	} {
		t.Run(tc.project, func(t *testing.T) {
			got := toolVars(tc.project)
			for _, v := range tc.absent {
				if strings.Contains(got, v) {
					t.Errorf("%s presets %s, which it provides itself: %q", tc.project, v, got)
				}
			}
			for _, v := range tc.present {
				if !strings.Contains(got, v) {
					t.Errorf("%s lost %s: %q", tc.project, v, got)
				}
			}
		})
	}
}

// A project that provides EVERY tool var would otherwise emit a bare `export`.
func TestToolVarsCanBeEmpty(t *testing.T) {
	saved := toolVarProvider
	defer func() { toolVarProvider = saved }()
	toolVarProvider = map[string]string{"SED": "x", "GREP": "x", "EGREP": "x", "FGREP": "x"}
	if got := toolVars("x"); got != "" {
		t.Errorf("toolVars = %q, want nothing at all", got)
	}
}

// The whole line still reaches the script for an ordinary package: libtool
// defaults these to /bin/grep, which does not exist in a from-scratch
// sovereign container.
func TestToolVarsStillExported(t *testing.T) {
	s := Wrap(WrapOptions{UserScript: "make", Target: darwinTgt(), Project: "acme.org/thing"})
	if !strings.Contains(s, `export SED="${SED:-sed}" GREP="${GREP:-grep}" EGREP="${EGREP:-grep -E}" FGREP="${FGREP:-grep -F}"`) {
		t.Errorf("the ordinary case lost its tool vars:\n%s", s)
	}
}

// The headerpad flag and its warning suppression travel together. Alone, the
// linker flag reaching a compile-only invocation is a hard error under the
// -Werror many configure probes use:
//
//	clang: error: -Wl,-headerpad_max_install_names: 'linker' input unused
//	  [-Werror,-Wunused-command-line-argument]
//
// and a failed probe does not stop a build, it turns a feature off silently.
func TestDarwinHeaderpadCarriesItsSuppression(t *testing.T) {
	s := Wrap(WrapOptions{
		UserScript: "make\n", Target: darwinTgt(), Host: darwinTgt(),
		ZpkgDir: "/opt/pkgx",
	})
	// LDFLAGS only. RUSTFLAGS carries the same flag as -C link-arg, which
	// rustc hands to the linker driver and nothing else — there is no
	// compile-only invocation on that path to be warned about.
	var ldflags string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "export LDFLAGS=") {
			ldflags = line
		}
	}
	if !strings.Contains(ldflags, "-Wl,-headerpad_max_install_names") {
		t.Fatalf("darwin LDFLAGS lost the install-name headroom: %q", ldflags)
	}
	if !strings.Contains(ldflags, "-Wno-unused-command-line-argument") {
		t.Errorf("headerpad without its suppression: %s", ldflags)
	}
}
