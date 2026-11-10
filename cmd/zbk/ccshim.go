package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ccShim implements the cc/gcc/c++/g++ multi-call helpers bk materialises into
// a build's libexec dir in pkgx-libc mode.
//
// A recipe is free to call the compiler by name rather than through $CC —
// sqlite's autosetup does ("No working C compiler found. Tried cc and gcc"),
// and autoconf probes `gcc` before `cc`. A bare compiler has none of the
// sysroot, crt and runtime flags the sovereign mode depends on, so it either
// fails outright or, worse, quietly links against whatever the build container
// happens to provide. The shim re-execs the real driver WITH those flags, which
// wrapper.go exported as ZBK_CC / ZBK_CXX.
func ccShim(name string, args []string, stderr io.Writer) int {
	varName := "ZBK_CC"
	if isCXXShim(name) {
		varName = "ZBK_CXX"
	}
	driver := strings.Fields(os.Getenv(varName))
	stencil := len(driver) > 0
	if !stencil {
		// No sovereign stencil (darwin, or linux on the system libc): the shim is
		// only here to impose the path map, so it drives the compiler of the
		// same name.
		driver = []string{fallbackDriver(name, os.Args[0])}
	}
	flags := driver[1:]
	if compileOnly(args) {
		flags = withoutLinkFlags(flags)
	}
	// Resolve the driver OURSELVES, skipping the directory this shim was
	// invoked from. Without that, a shim named after the driver finds
	// itself and re-execs forever — which is why `clang` and `clang++`
	// were left unshimmed, and why the 13 recipes that call clang by name
	// got a bare compiler with no sysroot (go-zpkg/bk#302).
	bin, err := resolveDriver(driver[0], os.Args[0])
	if err != nil {
		if !stencil {
			// $ZBK_CC is EMPTY here, so blaming it sends the reader to a
			// variable that is doing nothing. The old wording said "$ZBK_CC
			// names a compiler that is not installed" while $ZBK_CC was unset
			// and the name asked for was the shim's own.
			tried := name + " is not"
			if base := shimBase(name); base != name {
				tried = "neither " + name + " nor " + base + " is"
			}
			err = fmt.Errorf("%s on PATH outside this shim's directory, and $%s is unset — nothing supplies a compiler for this build", tried, varName)
		}
		fmt.Fprintf(stderr, "zbk %s: %v\n", name, err)
		return 127
	}
	all := append(append([]string{}, flags...), args...)
	// -ffile-prefix-map goes LAST, after whatever the recipe passed: it is an
	// option of the driver invocation, so a recipe that replaces CFLAGS wholesale
	// cannot drop it. A compiler that does not know it (GCC < 8, Clang < 10)
	// exits non-zero with its own "unknown argument" error; we never retry
	// without it, because a silent retry is the bug this shim exists to prevent.
	if m := os.Getenv(prefixMapEnv); m != "" {
		all = append(all, "-ffile-prefix-map="+m)
	}
	// At the LINK step only, darwin: ld64's debug map records the object files'
	// absolute paths (OSO stabs), which no compiler flag reaches. `-oso_prefix`
	// removes the prefix from them and keeps the map (no -S). ld rejecting it
	// fails the link, and there is no retry without it. (ld(1): "-oso_prefix
	// prefix-path: When generating the debug map, the linker will remove the
	// specified prefix-path from the path in OSO symbols.")
	if p := os.Getenv(osoPrefixEnv); p != "" && !compileOnly(args) {
		all = append(all, "-Wl,-oso_prefix,"+p)
	}
	cmd := execCommand(bin, all...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errorsAs(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(stderr, "zbk %s: %v\n", name, err)
		return 127
	}
	return 0
}

// prefixMapEnv carries OLD=NEW for -ffile-prefix-map; buildscript.Wrap exports
// it from the build's actual cache root.
const prefixMapEnv = "ZBK_FILE_PREFIX_MAP"

// osoPrefixEnv carries the cache root for ld64's -oso_prefix; Wrap exports it
// for darwin targets only.
const osoPrefixEnv = "ZBK_OSO_PREFIX"

// shimBase strips a triple prefix: x86_64-pc-linux-gnu-gcc -> gcc.
func shimBase(name string) string {
	// The "-" boundary makes at most one base match ("x-gcc" ends in "-gcc",
	// not in "-cc").
	for _, base := range compilerShimBases {
		if name == base || strings.HasSuffix(name, "-"+base) {
			return base
		}
	}
	return name
}

// fallbackDriver is the compiler a shim drives when no sovereign stencil set
// $ZBK_CC: the EXACT name it was invoked as when that exists on PATH, and the
// bare base otherwise.
//
// ⛔⛔ THE EXACT NAME FIRST, BECAUSE FOR A WINDOWS CROSS BUILD IT IS THE ONLY
// COMPILER THERE. bk sets no $ZBK_CC for windows — "its compiler comes from the
// recipe's llvm-mingw dep" (buildscript/wrapper.go) — and compilerShimsFor
// shims the TRIPLE-PREFIXED spellings, which this shim dir then puts FIRST on
// PATH. So `x86_64-w64-mingw32-gcc` reached the shim, shimBase reduced it to
// `gcc`, and the build died on a name llvm-mingw does not ship:
//
//	x86_64-w64-mingw32-gcc -O3 -Wall -c -o adler32.o adler32.c
//	bk gcc: gcc is not on PATH outside …/build.libexec
//
// while `x86_64-w64-mingw32-gcc` sat in the llvm-mingw bottle's bin, shadowed
// by our own shim. The doc comment above said the shim "drives the compiler of
// the same name" and shimBase made that false for every prefixed spelling.
//
// ⛔ AND THE BASE SECOND, BECAUSE STRIPPING IS NOT A MISTAKE. autoconf probes
// `x86_64-pc-linux-gnu-gcc`, which NOTHING installs under that name on a
// sovereign linux build; reducing it to `gcc` is what makes libisl configure
// (see compilerShimsFor). Trying the exact name first is strictly more
// capable: it changes the answer only where that name actually exists.
func fallbackDriver(name, self string) string {
	if _, err := resolveDriver(name, self); err == nil {
		return name
	}
	return shimBase(name)
}

// compileOnly reports whether this invocation stops before linking: -c, -S and
// -E all produce an object, assembly or preprocessed text and never run a
// linker.
func compileOnly(args []string) bool {
	for _, a := range args {
		switch a {
		case "-c", "-S", "-E":
			return true
		}
	}
	return false
}

// withoutLinkFlags drops the driver flags that only mean something when
// linking.
//
// bk hands the same sovereign flags to every invocation, and clang warns about
// the link ones when it is merely compiling. That warning is normally harmless
// — bk also passes -Wno-unused-command-line-argument — but a caller may ask for
// it back as an error, and the Linux kernel does exactly that:
//
//	-Werror=unused-command-line-argument
//
// -Werror=X re-enables X even when -Wno-X came earlier, and bk's flags are
// placed first, so the kernel wins on position and every compile-only step
// fails. Worse, kbuild decides which warnings to disable by PROBING the
// compiler with a trivial compile: those probes fail too, so the kernel
// concludes the compiler supports none of the warnings it wanted to turn off
// and loses -Wno-address-of-packed-member and its neighbours as well. One
// collision, a cascade of unrelated-looking errors.
//
// Removing the flags where they mean nothing settles it for every caller
// instead of adding a -Wno- for each one that notices.
func withoutLinkFlags(flags []string) []string {
	out := flags[:0:0]
	for _, f := range flags {
		if strings.HasPrefix(f, "-L") || strings.HasPrefix(f, "--rtlib=") ||
			strings.HasPrefix(f, "-fuse-ld=") || strings.HasPrefix(f, "--unwindlib=") {
			continue
		}
		out = append(out, f)
	}
	return out
}

// seams so the shim's failure branches are testable without a real compiler.
var execCommand = exec.Command

// errorsAs is errors.As, named so the shim reads without an import alias.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

// isCompilerShim reports whether a name is one of the compiler shims bk
// materialises: the bare `cc`/`gcc`/`c++`/`g++`, or a triple-prefixed spelling
// of one — `x86_64-pc-linux-gnu-gcc` is what autoconf looks for first, and
// finding the bare compiler instead of the shim is how libisl's configure got
// a gcc with none of the sovereign flags and reported
//
//	configure: error: C compiler cannot create executables
//
// Matched by suffix so this stays level with buildscript's list without
// repeating every triple.
func isCompilerShim(name string) bool {
	for _, base := range compilerShimBases {
		if name == base || strings.HasSuffix(name, "-"+base) {
			return true
		}
	}
	return false
}

// isCXXShim picks the C++ driver. By SUFFIX, so a triple-prefixed name is
// routed like its bare one: `s390x-ibm-linux-gnu-g++` is a C++ compiler and
// used to fall through to ZBK_CC, which would have handed a C++ build the C
// driver with no libc++ headers.
func isCXXShim(name string) bool {
	for _, base := range []string{"c++", "g++", "clang++"} {
		if name == base || strings.HasSuffix(name, "-"+base) {
			return true
		}
	}
	return false
}

// compilerShimBases is the single list of names that are shims, shared with
// buildscript's materialiser so the set that is CREATED and the set that is
// DISPATCHED cannot drift apart. They did not drift, but they were two
// literals saying the same thing, which is the same bet.
var compilerShimBases = []string{"cc", "gcc", "c++", "g++", "clang", "clang++"}

// resolveDriver finds the real compiler for a shim, skipping the directory
// the shim itself lives in.
//
// # WHY A SHIM CANNOT JUST EXEC ITS DRIVER BY NAME
//
// $ZBK_CC is `clang <sovereign flags>`, and the shim dir is FIRST on PATH.
// So a shim named `clang` that exec'd "clang" would find itself, forever.
// That is the whole reason `clang` and `clang++` were kept out of the shim
// set — and the cost of keeping them out is measurable: of the pantry's
// recipes, 77 set CC or CXX in an `env:` block, overwhelmingly to the bare
// words `clang`, `gcc`, `clang++`, `g++`. A recipe's env is emitted AFTER
// the sovereign preamble and replaces the variable whole, so every one of
// those builds with no --sysroot, no -isystem and no crt path. gnu.org/
// autoconf and gnu.org/automake fail exactly there:
//
//	checking for gcc... clang
//	checking whether the C compiler works... no
//	configure: error: C compiler cannot create executables
//
// Skipping our own directory removes the loop, so the names can be shimmed
// and the doctrine holds: a sovereign setting that must apply to every
// recipe goes where the SHIM imposes it, not in a variable recipes declare.
//
// An absolute or relative path is taken as given — only a bare name is
// looked up, because only a bare name can resolve back to the shim.
func resolveDriver(driver, self string) (string, error) {
	if strings.ContainsRune(driver, os.PathSeparator) {
		return driver, nil
	}
	selfDir := ""
	if abs, err := filepath.Abs(filepath.Dir(self)); err == nil {
		selfDir = abs
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if abs, err := filepath.Abs(dir); err == nil && abs == selfDir {
			continue // our own shim dir
		}
		cand := filepath.Join(dir, driver)
		if fi, err := osStat(cand); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("%s is not on PATH outside %s — $ZBK_CC names a compiler that is not installed", driver, selfDir)
}

// osStat is a seam.
var osStat = os.Stat
