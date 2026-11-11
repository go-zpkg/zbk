package buildscript

import (
	"fmt"
	"strings"

	"github.com/go-zpkg/zbk/target"
)

// TestWrapOptions carries what a recipe's test: block needs around it.
//
// The schema calls the test "a post-build sanity test run in a fresh sandbox",
// and the sandbox is the whole point: it answers "does what we PUBLISHED
// work", which is a different question from "did the build succeed". So this
// deliberately does NOT reuse WrapOptions.
//
// What a build script has and a test script must not:
//
//	CFLAGS/LDFLAGS/rpath  a test may COMPILE — 260 recipes' do — but against
//	                      the package as shipped. A flag set that made the
//	                      artefact link would mask a bottle whose own headers
//	                      or rpath are wrong, which is the thing worth
//	                      catching. The compiler itself is supplied; the
//	                      build's flags are not.
//	CMAKE_PREFIX_PATH     the whole store (go-zpkg/bk#164). A test that found
//	                      a header there would be finding it by accident.
//	$SRCROOT / the build  the sources are gone by then, and a test that reads
//	                      tree                  them is testing the tree and
//	                      not the package.
//
// What it keeps is close to what a user has: the package itself, whatever the
// recipe declares under test.dependencies, the recipe's own fixture files, a
// fresh HOME and an empty directory to work in — plus a compiler when the
// test's own script calls one.
type TestWrapOptions struct {
	UserScript string // the test node, already rendered by Generate
	// Package is the pkgspec of the package UNDER TEST, and it must name an
	// exact version. `bk test gnu.org/gawk` after building 5.4.1 with 5.3.0
	// still published would otherwise test 5.3.0 and report on the wrong
	// bytes — a green result about a build that never happened.
	Package string
	// Deps are the recipe's test.dependencies, already reduced for the target
	// and rendered as pkgspecs. They are a SEPARATE map from build and runtime
	// dependencies: a test may need a fixture generator or a diff tool that
	// the package itself must not carry.
	Deps []string
	// Compiler asks for one in the test environment.
	//
	// The first version of this file said a test may not have a compiler,
	// because "a consumer installing this package gets none". Measured
	// against pantry 2df061b with `bk tools --scope test --all`, that is
	// wrong: 260 recipes' tests call a compiler (cc 193, c++ 38, gcc 13,
	// g++ 7, clang 6, clang++ 6 — 260 distinct, not the sum of 263, because
	// three call two of them), and only 6 declare llvm.org. A recipe's test
	// compiling a five-line program against the headers it just shipped IS
	// the convention here — zlib.net's is `cc test.c -lz` — and a sandbox
	// that refuses would have reported 260 false failures.
	//
	// Asked per test rather than always, from the rendered script's own
	// command set, so the 1500-odd tests that compile nothing do not install
	// a compiler to not use it.
	Compiler bool
	Home     string        // a fresh HOME, created by the script
	Sandbox  string        // the empty directory the test runs in
	ZpkgDir  string        // $ZPKG_DIR, so the eval resolves where the build published
	ZpkgxBin string        // path to the pkgx binary
	BashPath string        // shebang interpreter (default /bin/bash)
	Host     target.Target // where we run — drives TMPDIR
	// ShimDir holds bk's compiler shims (cc, gcc, c++, g++ and their
	// triple-prefixed spellings), materialised by the caller with
	// WriteLibexecFor. It is prepended to PATH in a scratch rootfs so a test
	// that calls `cc` by name — which 194 of the pantry's do — gets the
	// sovereign driver rather than a bare clang with no libc.
	//
	// Empty is allowed and means "no shims": the preamble then falls back to
	// putting the flags in $CC, which is what it used to do and what reaches
	// almost nothing.
	ShimDir string
}

// EnvFailExit is the status the test script exits with when `pkgx +…` could
// not assemble the environment — as opposed to the test itself failing.
//
// The two were one for a while, and the s390x seed's first sweep shows what
// that costs: of nine reported failures, FIVE never ran a line of their test
// block. invisible-island.net/ncurses wants github.com/tmux/tmux ^3 as a
// test dependency and no s390x tmux exists anywhere; gnu.org/readline's
// closure needs libCNS.so, which pkgx's soname map does not name. Neither is
// a bottle that does not work, and calling them failures would file bugs
// against packages for an incomplete registry.
//
// 69 is sysexits' EX_UNAVAILABLE, which is what happened. A test that exits
// 69 on its own would be read as this — and would be saying very nearly the
// same thing, which is why the collision is tolerable where an arbitrary
// number would not be.
const EnvFailExit = 69

// WrapTest renders the runnable script for a recipe's test: block.
//
// NO `set -x`, and the first version of this had it with a reason that was
// right about diagnosis and wrong about correctness.
//
// The trace goes to stderr, and a test that captures stderr captures it:
//
//	out=$("{{prefix}}/bin/iconv" --version 2>&1 | head -1)
//	→ out='+ /…/bin/iconv --version'
//
// gnu.org/glibc reported a broken iconv on nothing but that. Measured on
// pantry 2df061b: 31 of the 1897 recipes with a test block capture stderr
// into a substitution, and every one of them would read its own trace.
//
// BASH_XTRACEFD would have kept both — the trace on a descriptor `2>&1`
// cannot reach — and mvdan.cc/sh ignores it, measured rather than assumed.
//
// So the trace is dropped. A missing trace makes a failure slower to read;
// a contaminated capture makes a WORKING package report FAIL, and a wrong
// answer is worse than a slow one. The generated script stays on disk beside
// the sandbox, which is where the commands can still be read.
func WrapTest(o TestWrapOptions) string {
	bash := o.BashPath
	if bash == "" {
		bash = "/bin/bash"
	}
	zpkgxBin := o.ZpkgxBin
	if zpkgxBin == "" {
		zpkgxBin = "zpkgx"
	}
	var b strings.Builder
	// `set -e`, and NOT pipefail. A build is one long script where a stage
	// failing mid-pipeline must stop it; a test is a list of assertions, and
	// `cmd | head -1` is how several of them read one line. Under pipefail
	// the producer takes SIGPIPE when head closes, and the assertion fails
	// for writing too much:
	//
	//	+ head -1
	//	FAIL gnu.org/glibc 2.44: exit status 141
	//
	// Measured on pantry 2df061b: 38 of the 1897 recipes with a test block
	// pipe into head or tail. None of them is broken.
	//
	// What pipefail would have caught — a producer dying while a later stage
	// succeeds — the common test shape catches anyway: in `foo | grep x`, a
	// dead foo writes nothing and grep fails on its own. That is exactly the
	// case go-zpkg/bk#162 opened with, muscle's
	// `(muscle --version 2>&1 || true) | grep '{{version.raw}}'`, where grep
	// is what reports the kill.
	//
	// Copied from Wrap when this file was written, which was not a decision.
	fmt.Fprintf(&b, "#!%s\n\nset -e\n\n", bash)
	fmt.Fprintf(&b, "export HOME=%q\n", o.Home)
	b.WriteString("export ZPKG_HOME=\"$HOME\"\n")
	b.WriteString("mkdir -p \"$HOME\"\n")
	if o.ZpkgDir != "" {
		fmt.Fprintf(&b, "export ZPKG_DIR=%q\n", o.ZpkgDir)
	}
	b.WriteString(tmpdirLine(o.Host) + "\n")

	// ONE eval, not the build's two. The build separates the tool closure from
	// the link closure because a build tool's runtime and the artefact's link
	// requirements answer different questions (see WrapOptions.ToolDeps). A
	// test has no artefact and no link step: everything it names is something
	// that has to RUN, so splitting them would invent a distinction the recipe
	// never made.
	writeDepEval(&b, zpkgxBin, o.testPlus(), "test", EnvFailExit)
	if o.ZpkgxBin != "" {
		fmt.Fprintf(&b, "export ZPKGX=%q\n", o.ZpkgxBin)
	}

	// After the eval, so the bottles are on disk and $ZPKG_DIR is set; before
	// the sandbox, so a test that compiles finds CC already pointing at a
	// libc it can use.
	if o.Compiler && o.Host.Platform == "linux" {
		b.WriteString("\n")
		for _, l := range sysrootPreamble(o.ShimDir) {
			b.WriteString(l + "\n")
		}
	}

	b.WriteString("\n")
	fmt.Fprintf(&b, "mkdir -p %q\n", o.Sandbox)
	fmt.Fprintf(&b, "cd %q\n\n", o.Sandbox)
	b.WriteString(strings.TrimRight(o.UserScript, "\n"))
	b.WriteString("\n")
	return b.String()
}

// testPlus renders the `+spec` list: the package under test FIRST, then its
// test dependencies.
//
// First so that when a test dependency's closure drags in another version of
// the same project, the package we were asked about is the one already in the
// environment. pkgx writes each variable as VAR="new${VAR:+:$VAR}" within one
// eval in the order given, so earlier wins the head of PATH.
func (o TestWrapOptions) testPlus() string {
	parts := make([]string, 0, len(o.Deps)+1)
	if o.Package != "" {
		parts = append(parts, `"+`+o.Package+`"`)
	}
	for _, d := range o.Deps {
		parts = append(parts, `"+`+d+`"`)
	}
	// Last, and only where the machine does not already have one: Wrap makes
	// the same exception for a darwin host, which builds with the system
	// toolchain. Appended after the recipe's own dependencies so a recipe
	// that names a compiler keeps the version it named.
	if o.Compiler && o.Host.Platform != "darwin" {
		parts = append(parts, `"+llvm.org"`)
		// And the libc it compiles against, on linux. A compiler with no libc
		// is not a compiler: in a SCRATCH rootfs there is no /usr/include and
		// no crt1.o, and clang reports
		//
		//	'stdlib.h' file not found
		//	cannot open Scrt1.o: No such file or directory
		//	C compiler cannot create executables
		//
		// which is nineteen of the twenty-seven gen1 test failures: the
		// environment, not the package. On a distribution these bottles are
		// installed and then UNUSED, because the sysroot flags below are
		// emitted only when the host has no libc of its own.
		if o.Host.Platform == "linux" {
			parts = append(parts, `"+gnu.org/glibc"`, `"+kernel.org/linux-headers"`,
				`"+gnu.org/binutils"`, `"+libcxx.llvm.org"`)
		}
	}
	return strings.Join(parts, " ")
}

// sysrootPreamble gives the test's compiler a libc WHEN THE HOST HAS NONE.
//
// The file comment above says a test gets the compiler and not the build's
// flags, because a flag set that made the artefact link would mask a bottle
// whose own headers or rpath are wrong. That is still true, and this does not
// weaken it: what is emitted here is the sysroot — where libc's headers and
// crt files are — and nothing the recipe chose. No recipe CFLAGS, no rpath,
// no CMAKE_PREFIX_PATH. A test must be able to produce a binary at all; it
// must not be handed the flags that made the artefact link.
//
// The reasoning the file was written with assumed a DISTRIBUTION, where the
// system supplies libc and withholding the build's flags leaves a working
// compiler. In the sovereign generation the rootfs is scratch and nothing
// supplies it, so withholding meant the test could not compile anything —
// and the assertion failed for the sandbox rather than for the package.
//
// Guarded at RUN TIME on the absence of a system header, not at generation
// time, for two reasons. The generator does not know what rootfs the script
// will run in — the same bk builds on a distribution and inside the chroot.
// And a distribution's script stays byte-for-byte what it was: the branch is
// not taken, so nothing about the 260 recipes that compile today changes.
//
// # SETTING $CC REACHED ALMOST NOTHING, AND THAT WAS MEASURABLE BEFOREHAND
//
// The first version of this exported CC and CXX and stopped there. Measured
// afterwards, on the second full sovereign generation: 16 of 23 test failures
// were a missing C header, and every one of them called the compiler BY NAME.
//
//	bk tools --scope test --all   →   cc 194, c++ 38, gcc 13, g++ 7,
//	                                  clang 7, clang++ 6
//
// Those are command names in command position. Not one of the 194 reads $CC.
// So the export was a fix that could not work, and the count that says so was
// available from a command in this repository before it was written.
//
// The build side had solved this years earlier and said why, in
// buildscript/libexec.go: "a recipe may call `cc` or `gcc` DIRECTLY, ignoring
// $CC". The same shims go on the test's PATH, pointed at the same $ZBK_CC. The
// test still gets the SYSROOT and nothing the recipe chose, so the rule this
// file is built on is unchanged — it is the delivery that was wrong.
//
// `clang` and `clang++` are deliberately NOT shimmed: $ZBK_CC's driver is
// clang, so a shim of that name would re-exec itself forever. The 13 recipes
// that call clang directly ask for a specific compiler and get it.
func sysrootPreamble(shimDir string) []string {
	out := []string{
		`# A compiler with no libc is not a compiler. On a distribution the`,
		`# system supplies one and this is skipped entirely; in a scratch`,
		`# rootfs the bottles installed above are the only libc there is.`,
		`if [ ! -e /usr/include/stdlib.h ]; then`,
	}
	for _, l := range sysrootResolve {
		out = append(out, "  "+l)
	}
	out = append(out,
		// ZBK_CC/ZBK_CXX are what the shims re-exec, exactly as a build's are.
		`  export ZBK_CC="clang `+SysrootCC+`"`,
		`  export ZBK_CXX="clang++ `+SysrootCXX+`"`,
	)
	if shimDir != "" {
		out = append(out,
			// FIRST on PATH: the llvm.org bottle puts its own cc there, and a
			// test picking that one is the failure this is here to end.
			fmt.Sprintf(`  export PATH=%q:"$PATH"`, shimDir),
			// $CC too, for the handful of tests that read it. It names the
			// shim rather than carrying the flags, so there is ONE place the
			// sysroot comes from and no invocation gets it twice.
			`  export CC="${CC:-cc}"`,
			`  export CXX="${CXX:-c++}"`,
		)
	} else {
		// No shim dir — the caller did not make one. The variables are all
		// that is left, and they are better than nothing for the tests that
		// do read them.
		out = append(out,
			`  export CC="${CC:-cc} `+SysrootCC+`"`,
			`  export CXX="${CXX:-c++} `+SysrootCXX+`"`,
		)
	}
	out = append(out,
		`  echo "test sandbox: no system libc, compiling against ${ZBK_GLIBC_PREFIX}" >&2`,
		`fi`,
	)
	return out
}
